variable "content_filters" {
  type = list(object({
    type            = string
    input_strength  = string
    output_strength = string
  }))
}

resource "aws_bedrock_guardrail" "dynamic" {
  name                      = "dynamic-guardrail"
  blocked_input_messaging   = "Blocked input."
  blocked_outputs_messaging = "Blocked output."

  content_policy_config {
    dynamic "filters_config" {
      for_each = var.content_filters
      content {
        type            = filters_config.value.type
        input_strength  = filters_config.value.input_strength
        output_strength = filters_config.value.output_strength
      }
    }
  }
}
