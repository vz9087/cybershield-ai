export const TICKET_STATUSES = ["new", "under_review", "confirmed", "false_report", "need_more_info", "resolved"] as const;
export type TicketStatus = typeof TICKET_STATUSES[number];

export const TICKET_TRANSITIONS: Record<TicketStatus, readonly TicketStatus[]> = {
  new: ["under_review"],
  under_review: ["confirmed", "false_report", "need_more_info"],
  confirmed: ["resolved"],
  false_report: ["resolved"],
  need_more_info: ["under_review", "confirmed", "false_report", "resolved"],
  resolved: [],
};

export function canTransitionTicket(from: TicketStatus, to: TicketStatus): boolean {
  return from === to || TICKET_TRANSITIONS[from].includes(to);
}

export function availableTicketStatuses(current: TicketStatus): TicketStatus[] {
  return [current, ...TICKET_TRANSITIONS[current]];
}
