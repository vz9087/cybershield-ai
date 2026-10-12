import { describe, expect, it } from "vitest";
import { awarenessQuestions, scoreAwarenessAnswers } from "./awareness";

describe("awareness quiz scoring integrity", () => {
  it("scores exactly one valid response for each distinct question", () => {
    const answers: { questionId: string; selected: number }[] = awarenessQuestions.map(question => ({ questionId: question.id, selected: question.answer }));
    expect(scoreAwarenessAnswers(answers).score).toBe(awarenessQuestions.length);
  });

  it("rejects repeated IDs even when the array has the expected length", () => {
    const answers = Array.from({ length: awarenessQuestions.length }, () => ({ questionId: "q1", selected: 2 }));
    expect(() => scoreAwarenessAnswers(answers)).toThrow("exactly once");
  });

  it("rejects indexes that do not refer to a displayed choice", () => {
    const answers: { questionId: string; selected: number }[] = awarenessQuestions.map(question => ({ questionId: question.id, selected: question.answer }));
    answers[0] = { questionId: awarenessQuestions[0].id, selected: 99 };
    expect(() => scoreAwarenessAnswers(answers)).toThrow("listed answer");
  });
});
