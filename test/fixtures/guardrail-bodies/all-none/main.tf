resource "aws_bedrock_guardrail" "permissive" {
  name                      = "permissive-guardrail"
  blocked_input_messaging   = "Blocked input."
  blocked_outputs_messaging = "Blocked output."

  content_policy_config {
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "NONE"
      output_strength = "NONE"
    }
    filters_config {
      type            = "HATE"
      input_strength  = "NONE"
      output_strength = "NONE"
    }
  }
}
