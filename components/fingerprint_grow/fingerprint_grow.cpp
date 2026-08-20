#include "fingerprint_grow.h"
#include "esphome/core/gpio.h"
#include "esphome/core/log.h"
#include <cinttypes>
#include <cstdlib>

namespace esphome::fingerprint_grow {

static const char *const TAG = "fingerprint_grow";

// Based on Adafruit's library: https://github.com/adafruit/Adafruit-Fingerprint-Sensor-Library

void FingerprintGrowComponent::update() {
  if (!this->security_ready_)
    return;
  if (this->enrollment_image_ > this->enrollment_buffers_) {
    this->finish_enrollment(this->save_fingerprint_());
    return;
  }

  if (this->has_sensing_pin_) {
    // A finger touch results in a low level (digital_read() == false)
    if (this->sensing_pin_->digital_read()) {
      ESP_LOGV(TAG, "No touch sensing");
      this->waiting_removal_ = false;
      if ((this->enrollment_image_ == 0) &&  // Not in enrolment process
          (millis() - this->last_transfer_ms_ > this->idle_period_to_sleep_ms_) && (this->is_sensor_awake_)) {
        this->sensor_sleep_();
      }
      return;
    } else if (!this->waiting_removal_) {
      this->finger_scan_start_callback_.call();
    }
  }

  if (this->waiting_removal_) {
    if ((!this->has_sensing_pin_) && (this->scan_image_(1) == NO_FINGER)) {
      ESP_LOGD(TAG, "Finger removed");
      this->waiting_removal_ = false;
    }
    return;
  }

  if (this->enrollment_image_ == 0) {
    this->scan_and_match_();
    return;
  }

  uint8_t result = this->scan_image_(this->enrollment_image_);
  if (result == NO_FINGER) {
    return;
  }
  this->waiting_removal_ = true;
  if (result != OK) {
    this->finish_enrollment(result);
    return;
  }
  this->enrollment_scan_callback_.call(this->enrollment_image_, this->enrollment_slot_);
  ++this->enrollment_image_;
}

void FingerprintGrowComponent::setup() {
  this->has_sensing_pin_ = (this->sensing_pin_ != nullptr);
  this->has_power_pin_ = (this->sensor_power_pin_ != nullptr);

  // Call pins setup, so we effectively apply the config generated from the yaml file.
  if (this->has_sensing_pin_) {
    this->sensing_pin_->setup();
  }
  if (this->has_power_pin_) {
    // Starts with output low (disabling power) to avoid glitches in the sensor
    this->sensor_power_pin_->digital_write(false);
    this->sensor_power_pin_->setup();

    // If the user didn't specify an idle period to sleep, applies the default.
    if (this->idle_period_to_sleep_ms_ == UINT32_MAX) {
      this->idle_period_to_sleep_ms_ = DEFAULT_IDLE_PERIOD_TO_SLEEP_MS;
    }
  }

  // Place the sensor in a known (sleep/off) state and sync internal var state.
  this->sensor_sleep_();
  delay(20);  // This delay guarantees the sensor will in fact be powered power.

  if (this->check_password_()) {
    if (this->new_password_ != std::numeric_limits<uint32_t>::max()) {
      if (this->set_password_())
        return;
    } else {
      if (this->get_parameters_()) {
        this->security_ready_ = true;
        this->spike_refresh_inventory();
        return;
      }
    }
  }
  // A protected module cannot be authenticated with the YAML defaults. Keep
  // the component alive so SPIKE can provide its secret over encrypted API.
  this->security_ready_ = false;
  this->spike_last_result_ = "provisioning_required";
  ESP_LOGW(TAG, "Fingerprint module awaits runtime identity verification");
}

void FingerprintGrowComponent::enroll_fingerprint(uint16_t finger_id, uint8_t num_buffers) {
  ESP_LOGI(TAG, "Starting enrollment in slot %d", finger_id);
  if (this->enrolling_binary_sensor_ != nullptr) {
    this->enrolling_binary_sensor_->publish_state(true);
  }
  this->enrollment_slot_ = finger_id;
  this->enrollment_buffers_ = num_buffers;
  this->enrollment_image_ = 1;
}

void FingerprintGrowComponent::finish_enrollment(uint8_t result) {
  if (result == OK) {
    this->enrollment_done_callback_.call(this->enrollment_slot_);
    this->get_fingerprint_count_();
  } else {
    if (this->enrollment_slot_ != ENROLLMENT_SLOT_UNUSED) {
      this->enrollment_failed_callback_.call(this->enrollment_slot_);
    }
  }
  this->enrollment_image_ = 0;
  this->enrollment_slot_ = ENROLLMENT_SLOT_UNUSED;
  if (this->enrolling_binary_sensor_ != nullptr) {
    this->enrolling_binary_sensor_->publish_state(false);
  }
  ESP_LOGI(TAG, "Finished enrollment");
}

void FingerprintGrowComponent::scan_and_match_() {
  if (this->has_sensing_pin_) {
    ESP_LOGD(TAG, "Scan and match");
  } else {
    ESP_LOGV(TAG, "Scan and match");
  }
  if (this->scan_image_(1) == OK) {
    this->waiting_removal_ = true;
    this->data_ = {SEARCH, 0x01, 0x00, 0x00, (uint8_t) (this->capacity_ >> 8), (uint8_t) (this->capacity_ & 0xFF)};
    switch (this->send_command_()) {
      case OK: {
        ESP_LOGD(TAG, "Fingerprint matched");
        uint16_t finger_id = ((uint16_t) this->data_[1] << 8) | this->data_[2];
        uint16_t confidence = ((uint16_t) this->data_[3] << 8) | this->data_[4];
        this->last_match_slot_ = finger_id;
        this->last_match_ms_ = millis();
        if (this->last_finger_id_sensor_ != nullptr) {
          this->last_finger_id_sensor_->publish_state(finger_id);
        }
        if (this->last_confidence_sensor_ != nullptr) {
          this->last_confidence_sensor_->publish_state(confidence);
        }
        this->finger_scan_matched_callback_.call(finger_id, confidence);
        break;
      }
      case NOT_FOUND:
        ESP_LOGD(TAG, "Fingerprint not matched to any saved slots");
        this->finger_scan_unmatched_callback_.call();
        break;
    }
  }
}

uint8_t FingerprintGrowComponent::scan_image_(uint8_t buffer) {
  if (this->has_sensing_pin_) {
    ESP_LOGD(TAG, "Getting image %d", buffer);
  } else {
    ESP_LOGV(TAG, "Getting image %d", buffer);
  }
  this->data_ = {GET_IMAGE};
  uint8_t send_result = this->send_command_();
  switch (send_result) {
    case OK:
      break;
    case NO_FINGER:
      if (this->has_sensing_pin_) {
        this->waiting_removal_ = true;
        ESP_LOGD(TAG, "Finger Misplaced");
        this->finger_scan_misplaced_callback_.call();
      } else {
        ESP_LOGV(TAG, "No finger");
      }
      return send_result;
    case IMAGE_FAIL:
      ESP_LOGE(TAG, "Imaging error");
      this->finger_scan_invalid_callback_.call();
      return send_result;
    default:
      ESP_LOGD(TAG, "Unknown Scan Error: %d", send_result);
      return send_result;
  }

  ESP_LOGD(TAG, "Processing image %d", buffer);
  this->data_ = {IMAGE_2_TZ, buffer};
  send_result = this->send_command_();
  switch (send_result) {
    case OK:
      ESP_LOGI(TAG, "Processed image %d", buffer);
      break;
    case IMAGE_MESS:
      ESP_LOGE(TAG, "Image too messy");
      this->finger_scan_invalid_callback_.call();
      break;
    case FEATURE_FAIL:
    case INVALID_IMAGE:
      ESP_LOGE(TAG, "Could not find fingerprint features");
      this->finger_scan_invalid_callback_.call();
      break;
  }
  return send_result;
}

uint8_t FingerprintGrowComponent::save_fingerprint_() {
  ESP_LOGI(TAG, "Creating model");
  this->data_ = {REG_MODEL};
  switch (this->send_command_()) {
    case OK:
      break;
    case ENROLL_MISMATCH:
      ESP_LOGE(TAG, "Scans do not match");
      [[fallthrough]];
    default:
      return this->data_[0];
  }

  ESP_LOGI(TAG, "Storing model");
  this->data_ = {STORE, 0x01, (uint8_t) (this->enrollment_slot_ >> 8), (uint8_t) (this->enrollment_slot_ & 0xFF)};
  switch (this->send_command_()) {
    case OK:
      ESP_LOGI(TAG, "Stored model");
      break;
    case BAD_LOCATION:
      ESP_LOGE(TAG, "Invalid slot");
      break;
    case FLASH_ERR:
      ESP_LOGE(TAG, "Error writing to flash");
      break;
  }
  return this->data_[0];
}

bool FingerprintGrowComponent::check_password_() {
  ESP_LOGD(TAG, "Checking password");
  this->data_ = {VERIFY_PASSWORD, (uint8_t) (this->password_ >> 24), (uint8_t) (this->password_ >> 16),
                 (uint8_t) (this->password_ >> 8), (uint8_t) (this->password_ & 0xFF)};
  switch (this->send_command_()) {
    case OK:
      ESP_LOGD(TAG, "Password verified");
      return true;
    case PASSWORD_FAIL:
      ESP_LOGE(TAG, "Wrong password");
      break;
  }
  return false;
}

bool FingerprintGrowComponent::set_password_() {
  ESP_LOGI(TAG, "Setting a new fingerprint module password");
  this->data_ = {SET_PASSWORD, (uint8_t) (this->new_password_ >> 24), (uint8_t) (this->new_password_ >> 16),
                 (uint8_t) (this->new_password_ >> 8), (uint8_t) (this->new_password_ & 0xFF)};
  if (this->send_command_() == OK) {
    ESP_LOGI(TAG, "New password successfully set");
    this->password_ = this->new_password_;
    return true;
  }
  return false;
}

bool FingerprintGrowComponent::get_parameters_() {
  ESP_LOGD(TAG, "Getting parameters");
  this->data_ = {READ_SYS_PARAM};
  if (this->send_command_() == OK) {
    ESP_LOGD(TAG, "Got parameters");        // Bear in mind data_[0] is the transfer status,
    if (this->status_sensor_ != nullptr) {  // the parameters table start at data_[1]
      this->status_sensor_->publish_state(((uint16_t) this->data_[1] << 8) | this->data_[2]);
    }
    this->system_identifier_code_ = ((uint16_t) this->data_[3] << 8) | this->data_[4];
    this->capacity_ = ((uint16_t) this->data_[5] << 8) | this->data_[6];
    this->security_level_ = ((uint16_t) this->data_[7] << 8) | this->data_[8];
    if (this->capacity_sensor_ != nullptr) {
      this->capacity_sensor_->publish_state(this->capacity_);
    }
    if (this->security_level_sensor_ != nullptr) {
      this->security_level_sensor_->publish_state(this->security_level_);
    }
    if (this->enrolling_binary_sensor_ != nullptr) {
      this->enrolling_binary_sensor_->publish_state(false);
    }
    this->get_fingerprint_count_();
    return true;
  }
  return false;
}

void FingerprintGrowComponent::get_fingerprint_count_() {
  ESP_LOGD(TAG, "Getting fingerprint count");
  this->data_ = {TEMPLATE_COUNT};
  if (this->send_command_() == OK) {
    ESP_LOGD(TAG, "Got fingerprint count");
    if (this->fingerprint_count_sensor_ != nullptr)
      this->fingerprint_count_sensor_->publish_state(((uint16_t) this->data_[1] << 8) | this->data_[2]);
  }
}

bool FingerprintGrowComponent::set_module_password_(uint32_t password) {
  this->data_ = {SET_PASSWORD, (uint8_t) (password >> 24), (uint8_t) (password >> 16),
                 (uint8_t) (password >> 8), (uint8_t) password};
  if (this->send_command_() != OK)
    return false;
  this->password_ = password;
  return true;
}

bool FingerprintGrowComponent::set_module_address_(uint32_t address) {
  this->data_ = {SET_ADDRESS, (uint8_t) (address >> 24), (uint8_t) (address >> 16),
                 (uint8_t) (address >> 8), (uint8_t) address};
  if (this->send_command_() != OK)
    return false;
  this->set_address(address);
  return true;
}

bool FingerprintGrowComponent::probe_security_(uint32_t password, uint32_t address) {
  this->set_address(address);
  this->password_ = password;
  if (!this->check_password_())
    return false;
  this->security_ready_ = true;
  return this->get_parameters_();
}

bool FingerprintGrowComponent::read_index_table_() {
  std::string occupied;
  const uint16_t page_count = (this->capacity_ + 255U) / 256U;
  for (uint16_t page = 0; page < page_count; page++) {
    this->data_ = {READ_INDEX_TABLE, (uint8_t) page};
    if (this->send_command_() != OK || this->data_.size() < 33U)
      return false;
    for (uint16_t byte_index = 0; byte_index < 32U; byte_index++) {
      const uint8_t bits = this->data_[byte_index + 1U];
      for (uint8_t bit = 0; bit < 8U; bit++) {
        const uint16_t slot = page * 256U + byte_index * 8U + bit;
        if (slot >= this->capacity_)
          break;
        if ((bits & (1U << bit)) != 0U) {
          if (!occupied.empty())
            occupied += ',';
          occupied += std::to_string(slot);
        }
      }
    }
  }
  this->spike_occupied_slots_ = occupied;
  return true;
}

bool FingerprintGrowComponent::spike_refresh_inventory() {
  if (!this->security_ready_ || !this->get_parameters_() || !this->read_index_table_()) {
    this->spike_last_result_ = "inventory_unavailable";
    return false;
  }
  this->spike_last_result_ = "verified";
  return true;
}

bool FingerprintGrowComponent::spike_verify(uint32_t password, uint32_t address) {
  if (!this->probe_security_(password, address)) {
    this->security_ready_ = false;
    this->spike_last_result_ = "verification_failed";
    return false;
  }
  return this->spike_refresh_inventory();
}

bool FingerprintGrowComponent::spike_provision(uint32_t password, uint32_t address, bool replacement) {
  if (password == 0U || address == 0U) {
    this->spike_last_result_ = "invalid_security_values";
    return false;
  }

  // Interrupted operations may have changed only one setting. Probe every
  // staged combination before deciding that this is a new replacement.
  bool authenticated = this->probe_security_(password, address) ||
                       this->probe_security_(password, 0xFFFFFFFFU) ||
                       this->probe_security_(0U, address) ||
                       this->probe_security_(0U, 0xFFFFFFFFU);
  if (!authenticated) {
    this->security_ready_ = false;
    this->spike_last_result_ = replacement ? "replacement_unreachable" : "provisioning_failed";
    return false;
  }

  if (this->password_ != password && !this->set_module_password_(password)) {
    this->spike_last_result_ = "password_change_failed";
    return false;
  }
  uint32_t current_address = ((uint32_t) this->address_[0] << 24) | ((uint32_t) this->address_[1] << 16) |
                             ((uint32_t) this->address_[2] << 8) | this->address_[3];
  if (current_address != address && !this->set_module_address_(address)) {
    this->spike_last_result_ = "address_change_failed";
    return false;
  }
  return this->spike_verify(password, address);
}

bool FingerprintGrowComponent::spike_reset_security(uint32_t password, uint32_t address) {
  // A previous attempt may have reset hardware before Home Assistant could
  // persist the final state. Accept that already-reset state idempotently.
  if (!this->probe_security_(password, address) && !this->probe_security_(0U, 0xFFFFFFFFU)) {
    this->spike_last_result_ = "verification_failed";
    return false;
  }
  if (this->password_ != 0U && !this->set_module_password_(0U)) {
    this->spike_last_result_ = "password_reset_failed";
    return false;
  }
  uint32_t current_address = ((uint32_t) this->address_[0] << 24) | ((uint32_t) this->address_[1] << 16) |
                             ((uint32_t) this->address_[2] << 8) | this->address_[3];
  if (current_address != 0xFFFFFFFFU && !this->set_module_address_(0xFFFFFFFFU)) {
    this->spike_last_result_ = "address_reset_failed";
    return false;
  }
  return this->spike_verify(0U, 0xFFFFFFFFU);
}

bool FingerprintGrowComponent::spike_verify_pending_match(uint32_t password, uint32_t address,
                                                           uint16_t finger_id) {
  if (this->last_match_slot_ != finger_id || millis() - this->last_match_ms_ > 5000U) {
    this->spike_last_result_ = "stale_match";
    return false;
  }
  // Consume locally before the UART operation so retries cannot replay it.
  this->last_match_slot_ = ENROLLMENT_SLOT_UNUSED;
  this->last_match_ms_ = 0;
  if (!this->spike_verify(password, address))
    return false;
  bool present = false;
  size_t start = 0;
  while (start <= this->spike_occupied_slots_.size()) {
    size_t end = this->spike_occupied_slots_.find(',', start);
    std::string part = this->spike_occupied_slots_.substr(start, end - start);
    if (!part.empty() && (uint16_t) strtoul(part.c_str(), nullptr, 10) == finger_id) {
      present = true;
      break;
    }
    if (end == std::string::npos)
      break;
    start = end + 1;
  }
  if (!present)
    this->spike_last_result_ = "slot_missing";
  return present;
}

void FingerprintGrowComponent::delete_fingerprint(uint16_t finger_id) {
  ESP_LOGI(TAG, "Deleting fingerprint in slot %d", finger_id);
  this->data_ = {DELETE, (uint8_t) (finger_id >> 8), (uint8_t) (finger_id & 0xFF), 0x00, 0x01};
  switch (this->send_command_()) {
    case OK:
      ESP_LOGI(TAG, "Deleted fingerprint");
      this->get_fingerprint_count_();
      break;
    case DELETE_FAIL:
      ESP_LOGE(TAG, "Reader failed to delete fingerprint");
      break;
  }
}

void FingerprintGrowComponent::delete_all_fingerprints() {
  ESP_LOGI(TAG, "Deleting all stored fingerprints");
  this->data_ = {DELETE_ALL};
  switch (this->send_command_()) {
    case OK:
      ESP_LOGI(TAG, "Deleted all fingerprints");
      this->get_fingerprint_count_();
      break;
    case DB_CLEAR_FAIL:
      ESP_LOGE(TAG, "Reader failed to clear fingerprint library");
      break;
  }
}

void FingerprintGrowComponent::led_control(bool state) {
  ESP_LOGD(TAG, "Setting LED");
  if (state) {
    this->data_ = {LED_ON};
  } else {
    this->data_ = {LED_OFF};
  }
  switch (this->send_command_()) {
    case OK:
      ESP_LOGD(TAG, "LED set");
      break;
    case PACKET_RCV_ERR:
    case TIMEOUT:
      break;
    default:
      ESP_LOGE(TAG, "Try aura_led_control instead");
      break;
  }
}

void FingerprintGrowComponent::aura_led_control(uint8_t state, uint8_t speed, uint8_t color, uint8_t count) {
  const uint32_t now = millis();
  const uint32_t elapsed = now - this->last_aura_led_control_;
  if (elapsed < this->last_aura_led_duration_) {
    delay(this->last_aura_led_duration_ - elapsed);
  }
  ESP_LOGD(TAG, "Setting Aura LED");
  this->data_ = {AURA_CONFIG, state, speed, color, count};
  switch (this->send_command_()) {
    case OK:
      ESP_LOGD(TAG, "Aura LED set");
      this->last_aura_led_control_ = millis();
      this->last_aura_led_duration_ = 10 * speed * count;
      break;
    case PACKET_RCV_ERR:
    case TIMEOUT:
      break;
    default:
      ESP_LOGE(TAG, "Try led_control instead");
      break;
  }
}

uint8_t FingerprintGrowComponent::transfer_(std::vector<uint8_t> &data_buffer) {
  while (this->available())
    this->read();
  this->write((uint8_t) (START_CODE >> 8));
  this->write((uint8_t) (START_CODE & 0xFF));
  this->write(this->address_[0]);
  this->write(this->address_[1]);
  this->write(this->address_[2]);
  this->write(this->address_[3]);
  this->write(COMMAND);

  uint16_t wire_length = data_buffer.size() + 2;
  this->write((uint8_t) (wire_length >> 8));
  this->write((uint8_t) (wire_length & 0xFF));

  uint16_t sum = (wire_length >> 8) + (wire_length & 0xFF) + COMMAND;
  for (auto data : data_buffer) {
    this->write(data);
    sum += data;
  }

  this->write((uint8_t) (sum >> 8));
  this->write((uint8_t) (sum & 0xFF));

  data_buffer.clear();

  uint8_t byte;
  uint16_t idx = 0, length = 0;

  for (uint16_t timer = 0; timer < 1000; timer++) {
    if (this->available() == 0) {
      delay(1);
      continue;
    }

    byte = this->read();

    switch (idx) {
      case 0:
        if (byte != (uint8_t) (START_CODE >> 8))
          continue;
        break;
      case 1:
        if (byte != (uint8_t) (START_CODE & 0xFF)) {
          idx = 0;
          continue;
        }
        break;
      case 2:
      case 3:
      case 4:
      case 5:
        if (byte != this->address_[idx - 2]) {
          idx = 0;
          continue;
        }
        break;
      case 6:
        if (byte != ACK) {
          idx = 0;
          continue;
        }
        break;
      case 7:
        length = (uint16_t) byte << 8;
        break;
      case 8:
        length |= byte;
        break;
      default:
        data_buffer.push_back(byte);
        if ((idx - 8) == length) {
          switch (data_buffer[0]) {
            case OK:
            case NO_FINGER:
            case IMAGE_FAIL:
            case IMAGE_MESS:
            case FEATURE_FAIL:
            case NO_MATCH:
            case NOT_FOUND:
            case ENROLL_MISMATCH:
            case BAD_LOCATION:
            case DELETE_FAIL:
            case DB_CLEAR_FAIL:
            case PASSWORD_FAIL:
            case INVALID_IMAGE:
            case FLASH_ERR:
              break;
            case PACKET_RCV_ERR:
              ESP_LOGE(TAG, "Reader failed to process request");
              break;
            default:
              ESP_LOGE(TAG, "Unknown response received from reader: 0x%.2X", data_buffer[0]);
              break;
          }
          this->last_transfer_ms_ = millis();
          return data_buffer[0];
        }
        break;
    }
    idx++;
  }
  ESP_LOGE(TAG, "No response received from reader");
  data_buffer.clear();
  data_buffer.push_back(TIMEOUT);
  this->last_transfer_ms_ = millis();
  return TIMEOUT;
}

uint8_t FingerprintGrowComponent::send_command_() {
  this->sensor_wakeup_();
  return this->transfer_(this->data_);
}

void FingerprintGrowComponent::sensor_wakeup_() {
  // Immediately return if there is no power pin or the sensor is already on
  if ((!this->has_power_pin_) || (this->is_sensor_awake_))
    return;

  this->sensor_power_pin_->digital_write(true);
  this->is_sensor_awake_ = true;

  uint8_t byte = TIMEOUT;

  // Wait for the byte HANDSHAKE_SIGN from the sensor meaning it is operational.
  for (uint16_t timer = 0; timer < WAIT_FOR_WAKE_UP_MS; timer++) {
    if (this->available() > 0) {
      byte = this->read();

      /* If the received byte is zero, the UART probably misinterpreted a raising edge on
       * the RX pin due the power up as byte "zero" - I verified this behaviour using
       * the esp32-arduino lib. So here we just ignore this fake byte.
       */
      if (byte != 0)
        break;
    }
    delay(1);
  }

  /* Lets check if the received by is a HANDSHAKE_SIGN, otherwise log an error
   * message and try to continue on the best effort.
   */
  if (byte == HANDSHAKE_SIGN) {
    ESP_LOGD(TAG, "Sensor has woken up!");
  } else if (byte == TIMEOUT) {
    ESP_LOGE(TAG, "Timed out waiting for sensor wake-up");
  } else {
    ESP_LOGE(TAG, "Received wrong byte from the sensor during wake-up: 0x%.2X", byte);
  }

  /* Next step, we must authenticate with the password. We cannot call check_password_ here
   * neither use data_ to store the command because it might be already in use by the caller
   * of send_command_()
   */
  std::vector<uint8_t> buffer = {VERIFY_PASSWORD, (uint8_t) (this->password_ >> 24), (uint8_t) (this->password_ >> 16),
                                 (uint8_t) (this->password_ >> 8), (uint8_t) (this->password_ & 0xFF)};

  if (this->transfer_(buffer) != OK) {
    ESP_LOGE(TAG, "Wrong password");
  }
}

void FingerprintGrowComponent::sensor_sleep_() {
  // Immediately return if the power pin feature is not implemented
  if (!this->has_power_pin_)
    return;

  this->sensor_power_pin_->digital_write(false);
  this->is_sensor_awake_ = false;
  ESP_LOGD(TAG, "Fingerprint sensor is now in sleep mode.");
}

void FingerprintGrowComponent::dump_config() {
  char sensing_pin_buf[GPIO_SUMMARY_MAX_LEN];
  char power_pin_buf[GPIO_SUMMARY_MAX_LEN];
  if (this->has_sensing_pin_) {
    this->sensing_pin_->dump_summary(sensing_pin_buf, sizeof(sensing_pin_buf));
  }
  if (this->has_power_pin_) {
    this->sensor_power_pin_->dump_summary(power_pin_buf, sizeof(power_pin_buf));
  }
  ESP_LOGCONFIG(TAG,
                "GROW_FINGERPRINT_READER:\n"
                "  System Identifier Code: 0x%.4X\n"
                "  Touch Sensing Pin: %s\n"
                "  Sensor Power Pin: %s",
                this->system_identifier_code_, this->has_sensing_pin_ ? sensing_pin_buf : "None",
                this->has_power_pin_ ? power_pin_buf : "None");
  if (this->idle_period_to_sleep_ms_ < UINT32_MAX) {
    ESP_LOGCONFIG(TAG, "  Idle Period to Sleep: %" PRIu32 " ms", this->idle_period_to_sleep_ms_);
  } else {
    ESP_LOGCONFIG(TAG, "  Idle Period to Sleep: Never");
  }
  LOG_UPDATE_INTERVAL(this);
  if (this->fingerprint_count_sensor_) {
    LOG_SENSOR("  ", "Fingerprint Count", this->fingerprint_count_sensor_);
    ESP_LOGCONFIG(TAG, "    Current Value: %u", (uint16_t) this->fingerprint_count_sensor_->get_state());
  }
  if (this->status_sensor_) {
    LOG_SENSOR("  ", "Status", this->status_sensor_);
    ESP_LOGCONFIG(TAG, "    Current Value: %u", (uint8_t) this->status_sensor_->get_state());
  }
  if (this->capacity_sensor_) {
    LOG_SENSOR("  ", "Capacity", this->capacity_sensor_);
    ESP_LOGCONFIG(TAG, "    Current Value: %u", (uint16_t) this->capacity_sensor_->get_state());
  }
  if (this->security_level_sensor_) {
    LOG_SENSOR("  ", "Security Level", this->security_level_sensor_);
    ESP_LOGCONFIG(TAG, "    Current Value: %u", (uint8_t) this->security_level_sensor_->get_state());
  }
  if (this->last_finger_id_sensor_) {
    LOG_SENSOR("  ", "Last Finger ID", this->last_finger_id_sensor_);
    ESP_LOGCONFIG(TAG, "    Current Value: %" PRIu32, (uint32_t) this->last_finger_id_sensor_->get_state());
  }
  if (this->last_confidence_sensor_) {
    LOG_SENSOR("  ", "Last Confidence", this->last_confidence_sensor_);
    ESP_LOGCONFIG(TAG, "    Current Value: %" PRIu32, (uint32_t) this->last_confidence_sensor_->get_state());
  }
}

}  // namespace esphome::fingerprint_grow
