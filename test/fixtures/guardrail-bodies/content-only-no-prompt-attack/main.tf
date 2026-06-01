resource "aws_bedrock_guardrail" "content_only" {
  name                      = "content-only-guardrail"
  blocked_input_messaging   = "Blocked input."
  blocked_outputs_messaging = "Blocked output."

  content_policy_config {
    filters_config {
      type            = "HATE"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
    filters_config {
      type            = "VIOLENCE"
      input_strength  = "MEDIUM"
      output_strength = "MEDIUM"
    }
  }
}
