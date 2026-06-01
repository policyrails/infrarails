resource "aws_bedrock_guardrail" "empty" {
  name                      = "empty-guardrail"
  blocked_input_messaging   = "Blocked input."
  blocked_outputs_messaging = "Blocked output."
}
