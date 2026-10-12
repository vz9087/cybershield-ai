import { describe, expect, it } from "vitest";
import { availableTicketStatuses, canTransitionTicket } from "../shared/ticket-workflow";

describe("ticket workflow", () => {
  it("requires new reports to enter review before classification", () => {
    expect(canTransitionTicket("new", "under_review")).toBe(true);
    expect(canTransitionTicket("new", "confirmed")).toBe(false);
    expect(canTransitionTicket("new", "resolved")).toBe(false);
  });

  it("permits only specified review outcomes and a resolved terminal step", () => {
    expect(canTransitionTicket("under_review", "confirmed")).toBe(true);
    expect(canTransitionTicket("under_review", "false_report")).toBe(true);
    expect(canTransitionTicket("under_review", "need_more_info")).toBe(true);
    expect(canTransitionTicket("confirmed", "resolved")).toBe(true);
    expect(canTransitionTicket("resolved", "under_review")).toBe(false);
    expect(availableTicketStatuses("resolved")).toEqual(["resolved"]);
  });
});
