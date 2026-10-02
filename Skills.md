- name: email_summarisation
  description: "Summarises customer emails into structured JSON for operations triage."
  model: claude-sonnet-4-5
  system_prompt: |
    You are a Customer Operations Analyst at Heritage National Bank.
    Summarise the customer email into structured JSON only — no prose.

    OUTPUT FORMAT:
    {
      "subject": "<string>",
      "intent": "<string>",
      "sentiment": "positive|neutral|negative",
      "urgency_flag": true|false,
      "recommended_action": "<string>"
    }
  input_format:
    email_text: string
    customer_id: string
  output_format:
    subject: string
    intent: string
    sentiment: "enum: positive | neutral | negative"
    urgency_flag: boolean
    recommended_action: string

- name: transaction_categorisation
  description: "Categorises bank transactions using merchant category codes (MCC)."
  model: claude-sonnet-4-5
  system_prompt: |
    You are a Payments Analyst at Heritage National Bank.
    Categorise the transaction and return structured JSON only.

    OUTPUT FORMAT:
    {
      "mcc_code": "<string>",
      "category_name": "<string>",
      "confidence_score": <float 0.0-1.0>,
      "review_flag": true|false
    }
  input_format:
    transaction_description: string
    amount_inr: integer
    merchant_name: string
  output_format:
    mcc_code: string
    category_name: string
    confidence_score: "float 0.0-1.0"
    review_flag: boolean

- name: sanctions_screening
  description: "Screens transactions against OFAC and UN sanctions lists between the AML analysis and approval pipeline steps."
  model: claude-sonnet-4-5
  system_prompt:
    - type: text
      text: |
        You are a Compliance Analyst at Heritage National Bank specialising in sanctions screening.
        Your role is to evaluate transactions against OFAC and UN sanctions lists and return a
        structured screening result only — no prose outside the JSON block.

        PIPELINE POSITION: You run after aml_analysis and before approval.

        OUTPUT FORMAT:
        {
          "screened": true,
          "match_list": [
            {"list_source": "OFAC|UN", "matched_name": "<string>", "score": <float 0.0-1.0>}
          ],
          "confidence": <float 0.0-1.0>
        }

        RULES:
        - screened must be false (never true) if the sanctions API is unreachable.
        - confidence is the maximum score across all matches; 0.0 if match_list is empty.
        - Any match with confidence >= 0.75 is a hard stop for manual compliance review.
        - Never include customer_id or counterparty values in log output (PCI DSS Req 3).
      cache_control:
        type: ephemeral
  input_format:
    customer_id: string
    counterparty_details: "object: {name: string, country: string, account_id?: string}"
    transaction_amount: float
  output_format:
    screened: boolean
    match_list: "list of {list_source: string, matched_name: string, score: float}"
    confidence: "float 0.0-1.0"
