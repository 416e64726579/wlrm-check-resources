
resource "helm_release" "wlrm-check-resources" {
  name  = "tf-wlrm-check-resources"
  chart = "wlrm-check-resources"

  set {
    name  = "schedule"
    value = "0 */3 * * *"
  }

  set {
    name  = "wallarm_api_host"
    value = var.wallarm_api_host
  }

  set {
    name  = "image"
    value = "awallarm/wlrm-check:0.0.3"
  }

  set_sensitive {
    name  = "wallarm_uuid"
    value = var.wallarm_api_uuid
  }

  set_sensitive {
    name  = "wallarm_secret"
    value = var.wallarm_api_secret
  }

  set_sensitive {
    name  = "telegram_token"
    value = var.telegram_token
  }

  set_sensitive {
    name  = "chat_id"
    value = var.chat_id
  }

}
