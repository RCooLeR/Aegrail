export type ModelPreset = {
  bestUse: string;
  label: string;
  rank: number;
  size: string;
  value: string;
};

export const autoModelValue = "";

export const modelPresets: ModelPreset[] = [
  {
    bestUse: "Best overall for source-code website security review",
    label: "Qwen2.5-Coder-14B-Instruct",
    rank: 1,
    size: "14B",
    value: "qwen2.5-coder:14b"
  },
  {
    bestUse: "Better general reasoning, reports, tool/function calling, structured output",
    label: "Mistral Small 3.2 24B Instruct",
    rank: 2,
    size: "24B",
    value: "mistral-small3.2:latest"
  },
  {
    bestUse: "Good coding alternative, efficient for local use",
    label: "DeepSeek-Coder-V2-Lite-Instruct",
    rank: 3,
    size: "16B MoE",
    value: "deepseek-coder-v2:16b"
  },
  {
    bestUse: "Good reasoning/general analysis, but less specifically code-security tuned",
    label: "Qwen3-14B",
    rank: 4,
    size: "14B",
    value: "qwen3:14b"
  },
  {
    bestUse: "Good code model, but older and less instruction/security-review friendly",
    label: "StarCoder2-15B",
    rank: 5,
    size: "15B",
    value: "starcoder2:15b"
  }
];

export function modelPresetLabel(value: string) {
  if (!value) {
    return "Auto ranked";
  }
  const preset = modelPresets.find((item) => item.value === value);
  return preset ? `${preset.rank}. ${preset.label}` : value;
}
