export const awarenessQuestions = [
  { id: "q1", question: "A message says your bank account will be blocked today and asks you to share an OTP. What should you do?", options: ["Reply with the OTP", "Click the link to verify", "Contact the bank through its official app or number", "Forward it to friends"], answer: 2, explanation: "Banks should not ask you to disclose an OTP. Verify independently through an official channel." },
  { id: "q2", question: "A login page is on HTTPS. Does that alone prove it is legitimate?", options: ["Yes, HTTPS always means safe", "No, phishing sites can also use HTTPS", "Only if it has a logo", "Only on mobile"], answer: 1, explanation: "HTTPS encrypts the connection but does not prove who operates the site." },
  { id: "q3", question: "A recruiter offers a guaranteed job after an upfront registration fee. Best next step?", options: ["Pay quickly", "Send ID documents", "Verify the company and role using independently found contact details", "Install the attached APK"], answer: 2, explanation: "Upfront fees and guaranteed offers are common employment-scam cues." },
  { id: "q4", question: "You receive an unexpected attachment named bank_update.apk. What is safest?", options: ["Install to see what it does", "Forward it to a group", "Do not install; verify with the sender through another channel", "Disable phone security"], answer: 2, explanation: "Never install unexpected applications. Static scanning cannot guarantee a file is safe." },
  { id: "q5", question: "How should you verify a link claiming to be from a delivery company?", options: ["Use the link in the message", "Search independently for the official site or app", "Reply with your address and code", "Trust the sender name"], answer: 1, explanation: "Use an official channel you reach independently rather than a message link." },
  { id: "q6", question: "A caller asks for your one-time verification code to stop a payment. What should you do?", options: ["Share it if the caller knows your name", "Read the code slowly", "Do not share it; hang up and contact the institution directly", "Send a screenshot"], answer: 2, explanation: "A one-time code is for you only; a legitimate support agent should not need it." },
  { id: "q7", question: "What is a safer password practice?", options: ["Reuse one memorable password", "Use a unique password for each important account and a password manager", "Write it in a public note", "Add your birth year to every password"], answer: 1, explanation: "Unique passwords limit damage if one service is compromised; a password manager helps." },
  { id: "q8", question: "A message says you won a prize but must pay a small fee to claim it. What is the warning sign?", options: ["A fee is normal", "Unexpected prize plus upfront payment is suspicious", "The message has a colorful logo", "It arrived during the day"], answer: 1, explanation: "Unexpected rewards tied to payment or urgency are common scam patterns." },
  { id: "q9", question: "A website address is g00gle.com. What should you notice?", options: ["It is the same as google.com", "A character substitution may indicate typosquatting", "HTTPS makes it official", "The spelling is irrelevant"], answer: 1, explanation: "A lookalike domain can imitate a brand; type or select the official domain directly." },
  { id: "q10", question: "You suspect a coworker's account is compromised. What should you do?", options: ["Ask them to send their password", "Report through your organization's official security channel", "Post details publicly", "Download a recovery tool from an unknown link"], answer: 1, explanation: "Use an approved reporting channel and avoid requesting or sharing credentials." },
] as const;

export function scoreAwarenessAnswers(answers: { questionId: string; selected: number }[]) {
  if (answers.length !== awarenessQuestions.length) throw new Error("Answer every quiz question exactly once.");
  const suppliedIds = new Set(answers.map(answer => answer.questionId));
  if (suppliedIds.size !== awarenessQuestions.length || awarenessQuestions.some(question => !suppliedIds.has(question.id))) {
    throw new Error("Answer every quiz question exactly once.");
  }
  const feedback = awarenessQuestions.map(question => {
    const answer = answers.find(item => item.questionId === question.id)!;
    if (answer.selected < 0 || answer.selected >= question.options.length) throw new Error("Choose a listed answer for each quiz question.");
    return { questionId: question.id, selected: answer.selected, correctAnswer: question.answer, correct: answer.selected === question.answer, explanation: question.explanation };
  });
  return { feedback, score: feedback.filter(item => item.correct).length };
}
