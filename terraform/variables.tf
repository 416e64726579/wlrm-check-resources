variable "wallarm_api_host" {
  type        = string
  default     = "api.wallarm.com"
  description = "The Wallarm API Host"
}

variable "wallarm_api_uuid" {
  type        = string
  description = "Wallarm API UUID"
}

variable "wallarm_api_secret" {
  type        = string
  description = "Wallarm API secret"
}

variable "telegram_token" {
  type        = string
  description = "Telegram Token for Wallarm Notification Bot"
}

variable "chat_id" {
  type        = string
  description = "Telegram chat ID for the support chat"
}

