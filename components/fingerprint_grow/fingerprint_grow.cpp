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
      if (this->set_password_()) {
        this->spike_security_state_ = "password_written";
        this->spike_last_result_ = "native_stage_1_complete";
        return;
      }
    } else {
      if (this->get_parameters_()) {
        this->security_ready_ = true;
        // Reading a factory-default module proves UART/Grow availability, but
        // it does not prove SPIKE replacement protection. Keep the inventory
        // observation while reporting that an explicit, Config Lock-protected
        // provisioning operation is still required. Otherwise a clean module
        // could announce "protected_ready" before any password or address
        // binding was written.
        if (this->spike_refresh_inventory()) {
          this->spike_last_result_ = "factory_authenticated";
          this->spike_security_state_ = "factory_default_ready";
        }
        return;
      }
    }
  }
  // A protected module may not answer at the factory address or may reject
  // the factory password. Keep the component alive so SPIKE can probe every
  // persisted security tuple over the encrypted API. A timeout against this
  // one tuple alone is not proof of a dead UART.
  this->security_ready_ = false;
  this->spike_security_state_ = "identity_verification_required";
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
    this->get_fingerprint_count_();
    if (this->security_ready_)
      this->spike_refresh_inventory();
    this->enrollment_done_callback_.call(this->enrollment_slot_);
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
      this->spike_last_result_ = "password_verified";
      return true;
    case PASSWORD_FAIL:
      ESP_LOGE(TAG, "Wrong password");
      this->spike_last_result_ = "wrong_password";
      return false;
    case TIMEOUT:
      ESP_LOGD(TAG, "Fingerprint module did not answer this security tuple");
      this->spike_last_result_ = "security_tuple_no_response";
      return false;
    case ADDRESS_MISMATCH:
    case ADDRESS_CODE_INCORRECT:
      ESP_LOGE(TAG, "Fingerprint module answered from an unexpected address");
      this->spike_last_result_ = "wrong_address";
      return false;
    case PACKET_RCV_ERR:
    case BAD_PACKET:
      ESP_LOGE(TAG, "Fingerprint module returned a malformed packet response");
      this->spike_last_result_ = "malformed_module_response";
      return false;
    default:
      ESP_LOGE(TAG, "Fingerprint module rejected the security command");
      this->spike_last_result_ = "security_command_rejected";
      return false;
  }
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
    if (this->data_.size() < 9U) {
      ESP_LOGE(TAG, "Fingerprint module returned a truncated parameters packet");
      this->spike_last_result_ = "malformed_module_response";
      this->spike_security_state_ = "grow_initialization_failed";
      return false;
    }
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
    if (this->data_.size() < 3U) {
      ESP_LOGE(TAG, "Fingerprint module returned a truncated template-count packet");
      this->spike_last_result_ = "malformed_module_response";
      return;
    }
    ESP_LOGD(TAG, "Got fingerprint count");
    if (this->fingerprint_count_sensor_ != nullptr)
      this->fingerprint_count_sensor_->publish_state(((uint16_t) this->data_[1] << 8) | this->data_[2]);
  }
}

bool FingerprintGrowComponent::set_module_password_(uint32_t password) {
  this->data_ = {SET_PASSWORD, (uint8_t) (password >> 24), (uint8_t) (password >> 16),
                 (uint8_t) (password >> 8), (uint8_t) password};
  if (this->send_command_() != OK) {
    this->spike_last_result_ = "password_change_failed";
    return false;
  }
  this->password_ = password;
  this->spike_security_state_ = "password_written";
  return true;
}

bool FingerprintGrowComponent::set_module_address_(uint32_t address) {
  this->data_ = {SET_ADDRESS, (uint8_t) (address >> 24), (uint8_t) (address >> 16),
                 (uint8_t) (address >> 8), (uint8_t) address};
  if (this->send_command_() != OK) {
    this->spike_last_result_ = "address_change_failed";
    return false;
  }
  this->set_address(address);
  this->spike_security_state_ = "address_written";
  return true;
}

bool FingerprintGrowComponent::probe_security_(uint32_t password, uint32_t address) {
  const uint32_t previous_address =
      ((uint32_t) this->address_[0] << 24) | ((uint32_t) this->address_[1] << 16) |
      ((uint32_t) this->address_[2] << 8) | this->address_[3];
  const uint32_t previous_password = this->password_;
  const bool previous_security_ready = this->security_ready_;
  this->set_address(address);
  this->password_ = password;
  if (!this->check_password_()) {
    this->set_address(previous_address);
    this->password_ = previous_password;
    this->security_ready_ = previous_security_ready;
    return false;
  }
  this->security_ready_ = true;
  this->spike_security_state_ = "security_pair_authenticated";
  if (!this->get_parameters_()) {
    this->set_address(previous_address);
    this->password_ = previous_password;
    this->security_ready_ = previous_security_ready;
    this->spike_last_result_ = "module_parameter_read_failed";
    this->spike_security_state_ = "grow_initialization_failed";
    return false;
  }
  this->spike_security_state_ = "grow_ready";
  return true;
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
    this->spike_security_state_ = "inventory_unavailable";
    return false;
  }
  this->spike_last_result_ = "verified";
  this->spike_security_state_ = "inventory_verified";
  return true;
}

bool FingerprintGrowComponent::spike_verify(uint32_t password, uint32_t address) {
  if (!this->probe_security_(password, address)) {
    this->security_ready_ = false;
    this->spike_security_state_ = "verification_failed";
    return false;
  }
  this->spike_security_state_ = "final_pair_verified";
  if (!this->spike_refresh_inventory())
    return false;
  this->spike_security_state_ = "protected_ready";
  this->spike_last_result_ = "verified";
  return true;
}

bool FingerprintGrowComponent::spike_advance(uint32_t password, uint32_t address, bool replacement,
                                             bool recovery, const std::string &requested_stage) {
  if (password == 0U || address == 0U) {
    this->spike_last_result_ = "invalid_security_values";
    this->spike_security_state_ = "error";
    return false;
  }
  const uint32_t current_address =
      ((uint32_t) this->address_[0] << 24) | ((uint32_t) this->address_[1] << 16) |
      ((uint32_t) this->address_[2] << 8) | this->address_[3];
  std::string stage = requested_stage.empty() ? this->spike_security_state_ : requested_stage;
  if (stage.empty() || stage == "identity_verification_required" || stage == "recovery_required" ||
      stage == "error")
    stage = "secret_staged";

  if (stage == "secret_staged") {
    // Initial modules and intentional replacements normally use the factory
    // tuple, so probe it first. Recovery normally resumes an interrupted or
    // already-protected operation, so probe the final pair first, followed by
    // each possible partial NVM update and the factory pair. A timeout against
    // one address is not evidence that UART is absent.
    const uint32_t initial_passwords[] = {0U, password, 0U, password};
    const uint32_t initial_addresses[] = {0xFFFFFFFFU, 0xFFFFFFFFU, address, address};
    const uint32_t recovery_passwords[] = {password, password, 0U, 0U};
    const uint32_t recovery_addresses[] = {address, 0xFFFFFFFFU, address, 0xFFFFFFFFU};
    const uint32_t *candidate_passwords = recovery ? recovery_passwords : initial_passwords;
    const uint32_t *candidate_addresses = recovery ? recovery_addresses : initial_addresses;
    bool authenticated = false;
    bool any_response = false;
    std::string strongest_failure;
    std::string strongest_failure_state;
    auto failure_rank = [](const std::string &reason) -> uint8_t {
      if (reason == "module_parameter_read_failed" || reason == "malformed_module_response")
        return 3U;
      if (reason == "wrong_password" || reason == "security_command_rejected")
        return 2U;
      return 1U;
    };
    for (size_t index = 0; index < 4U && !authenticated; index++) {
      bool duplicate = false;
      for (size_t earlier = 0; earlier < index; earlier++) {
        if (candidate_passwords[index] == candidate_passwords[earlier] &&
            candidate_addresses[index] == candidate_addresses[earlier]) {
          duplicate = true;
          break;
        }
      }
      if (duplicate)
        continue;
      authenticated = this->probe_security_(candidate_passwords[index], candidate_addresses[index]);
      if (authenticated || this->spike_last_result_ != "security_tuple_no_response") {
        any_response = true;
        if (!authenticated &&
            (strongest_failure.empty() ||
             failure_rank(this->spike_last_result_) > failure_rank(strongest_failure))) {
          strongest_failure = this->spike_last_result_;
          strongest_failure_state = this->spike_security_state_;
        }
      }
    }
    if (!authenticated) {
      this->security_ready_ = false;
      if (!any_response) {
        this->spike_last_result_ = "security_tuple_no_response";
        this->spike_security_state_ = replacement ? "replacement_verification_failed" : "recovery_required";
      } else {
        this->spike_last_result_ = strongest_failure.empty()
                                       ? (replacement ? "replacement_authentication_failed"
                                                      : "security_authentication_failed")
                                       : strongest_failure;
        this->spike_security_state_ =
            strongest_failure_state.empty()
                ? (replacement ? "replacement_verification_failed" : "recovery_required")
                : strongest_failure_state;
      }
      return false;
    }
    this->spike_last_result_ = "authenticated";
    this->spike_security_state_ =
        (this->password_ == 0U &&
         (((uint32_t) this->address_[0] << 24) | ((uint32_t) this->address_[1] << 16) |
          ((uint32_t) this->address_[2] << 8) | this->address_[3]) == 0xFFFFFFFFU)
            ? "factory_authenticated"
            : "persisted_pair_authenticated";
    return true;
  }

  if (stage == "factory_authenticated" || stage == "persisted_pair_authenticated" ||
      stage == "password_write_pending") {
    if (this->password_ != password) {
      this->spike_security_state_ = "password_write_pending";
      if (!this->set_module_password_(password)) {
        this->spike_security_state_ = "recovery_required";
        return false;
      }
    } else {
      this->spike_security_state_ = "password_written";
      this->spike_last_result_ = "password_already_current";
    }
    return true;
  }

  if (stage == "password_written") {
    if (!this->probe_security_(password, current_address)) {
      this->spike_last_result_ = "password_verification_failed";
      this->spike_security_state_ = "recovery_required";
      return false;
    }
    this->spike_security_state_ = "password_verified";
    this->spike_last_result_ = "password_verified";
    return true;
  }

  if (stage == "password_verified" || stage == "address_write_pending") {
    if (current_address != address) {
      this->spike_security_state_ = "address_write_pending";
      if (!this->set_module_address_(address)) {
        this->spike_security_state_ = "recovery_required";
        return false;
      }
    } else {
      this->spike_security_state_ = "address_written";
      this->spike_last_result_ = "address_already_current";
    }
    return true;
  }

  if (stage == "address_written") {
    if (!this->probe_security_(password, address)) {
      this->spike_last_result_ = "final_pair_verification_failed";
      this->spike_security_state_ = "recovery_required";
      return false;
    }
    this->spike_security_state_ = "final_pair_verified";
    this->spike_last_result_ = "final_pair_verified";
    return true;
  }

  if (stage == "final_pair_verified") {
    return this->spike_refresh_inventory();
  }

  if (stage == "inventory_verified" || stage == "protected_ready") {
    this->spike_security_state_ = "protected_ready";
    this->spike_last_result_ = "verified";
    return true;
  }

  this->spike_last_result_ = "unsupported_provision_stage";
  this->spike_security_state_ = "error";
  return false;
}

bool FingerprintGrowComponent::spike_provision(uint32_t password, uint32_t address, bool replacement,
                                               bool recovery) {
  std::string stage = "secret_staged";
  for (uint8_t step = 0; step < 8U; step++) {
    if (!this->spike_advance(password, address, replacement, recovery, stage))
      return false;
    stage = this->spike_security_state_;
    if (stage == "protected_ready")
      return true;
    if (stage == "inventory_verified")
      return this->spike_advance(password, address, replacement, recovery, stage);
  }
  return this->spike_security_state_ == "protected_ready";
}

bool FingerprintGrowComponent::spike_reset_security(uint32_t password, uint32_t address) {
  // A previous attempt may have reset hardware before Home Assistant could
  // persist the final state. Accept that already-reset state idempotently.
  bool authenticated = this->probe_security_(password, address);
  if (!authenticated)
    authenticated = this->probe_security_(0U, 0xFFFFFFFFU);
  if (!authenticated) {
    this->spike_security_state_ = "recovery_required";
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
  if (!this->spike_verify(0U, 0xFFFFFFFFU))
    return false;
  this->spike_security_state_ = "factory_default_ready";
  return true;
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
      if (this->security_ready_)
        this->spike_refresh_inventory();
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
      if (this->security_ready_)
        this->spike_refresh_inventory();
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
  const uint8_t request_command = data_buffer.empty() ? 0U : data_buffer[0];
  const uint32_t requested_new_address =
      request_command == SET_ADDRESS && data_buffer.size() >= 5U
          ? ((uint32_t) data_buffer[1] << 24) | ((uint32_t) data_buffer[2] << 16) |
                ((uint32_t) data_buffer[3] << 8) | data_buffer[4]
          : 0U;
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
  bool received_any_byte = false;
  bool response_address_mismatch = false;
  uint8_t response_address[4] = {0U, 0U, 0U, 0U};
  const bool broadcast_address = this->address_[0] == 0xFF && this->address_[1] == 0xFF &&
                                 this->address_[2] == 0xFF && this->address_[3] == 0xFF;

  for (uint16_t timer = 0; timer < 1000; timer++) {
    if (this->available() == 0) {
      delay(1);
      continue;
    }

    byte = this->read();
    received_any_byte = true;

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
        response_address[idx - 2] = byte;
        if (byte != this->address_[idx - 2])
          response_address_mismatch = true;
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
        if (length < 3U || length > MAX_ACK_PACKET_LENGTH) {
          ESP_LOGE(TAG, "Fingerprint module returned an invalid ACK length: %u", length);
          data_buffer.clear();
          data_buffer.push_back(BAD_PACKET);
          this->last_transfer_ms_ = millis();
          return BAD_PACKET;
        }
        data_buffer.reserve(length);
        break;
      default:
        data_buffer.push_back(byte);
        if ((idx - 8) == length) {
          const size_t payload_size = data_buffer.size() - 2U;
          uint16_t expected_checksum = ACK + (length >> 8) + (length & 0xFF);
          for (size_t payload_index = 0; payload_index < payload_size; payload_index++)
            expected_checksum += data_buffer[payload_index];
          const uint16_t received_checksum =
              ((uint16_t) data_buffer[payload_size] << 8) | data_buffer[payload_size + 1U];
          if (expected_checksum != received_checksum) {
            ESP_LOGE(TAG, "Fingerprint module ACK checksum mismatch");
            data_buffer.clear();
            data_buffer.push_back(BAD_PACKET);
            this->last_transfer_ms_ = millis();
            return BAD_PACKET;
          }
          const uint32_t response_address_value =
              ((uint32_t) response_address[0] << 24) |
              ((uint32_t) response_address[1] << 16) |
              ((uint32_t) response_address[2] << 8) |
              response_address[3];
          // SetAdder implementations differ: some acknowledge with the old
          // address and others immediately use the newly written address.
          const bool new_address_ack =
              request_command == SET_ADDRESS && response_address_value == requested_new_address;
          if (response_address_mismatch && !broadcast_address && !new_address_ack) {
            ESP_LOGE(TAG, "Fingerprint module ACK address does not match the requested address");
            data_buffer.clear();
            data_buffer.push_back(ADDRESS_MISMATCH);
            this->last_transfer_ms_ = millis();
            return ADDRESS_MISMATCH;
          }
          if (broadcast_address) {
            this->set_address(response_address_value);
          }
          data_buffer.resize(payload_size);
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
            case ADDRESS_CODE_INCORRECT:
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
  if (received_any_byte) {
    ESP_LOGE(TAG, "Fingerprint module returned bytes without a valid ACK packet");
    data_buffer.clear();
    data_buffer.push_back(BAD_PACKET);
    this->last_transfer_ms_ = millis();
    return BAD_PACKET;
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
