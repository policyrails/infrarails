# Two guardrails with different posture, plus an agent that attaches the strong
# one by reference - exercises one-finding-per-guardrail and Decision B
# (attaching-agent enrichment).

resource "aws_bedrock_guardrail" "strong" {
  name                      = "strong-guardrail"
  blocked_input_messaging   = "Blocked input."
  blocked_outputs_messaging = "Blocked output."

  content_policy_config {
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "NONE"
    }
    filters_config {
      type            = "HATE"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
  }

  topic_policy_config {
    topics_config {
      name       = "investment_advice"
      type       = "DENY"
      definition = "Providing personalised investment advice."
    }
  }
}

resource "aws_bedrock_guardrail" "weak" {
  name                      = "weak-guardrail"
  blocked_input_messaging   = "Blocked input."
  blocked_outputs_messaging = "Blocked output."

  content_policy_config {
    filters_config {
      type            = "HATE"
      input_strength  = "NONE"
      output_strength = "NONE"
    }
  }
}

resource "aws_bedrockagent_agent" "support_bot" {
  agent_name              = "support-bot"
  agent_resource_role_arn = "arn:aws:iam::123456789012:role/bedrock-agent"
  foundation_model        = "anthropic.claude-3-sonnet-20240229-v1:0"
  instruction             = "You are a helpful support bot."

  guardrail_configuration {
    guardrail_identifier = aws_bedrock_guardrail.strong.guardrail_id
    guardrail_version    = "1"
  }
}
