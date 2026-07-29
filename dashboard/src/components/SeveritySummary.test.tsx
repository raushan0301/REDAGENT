import { render, screen } from "@testing-library/react";
import { SeveritySummary } from "./SeveritySummary";

describe("SeveritySummary", () => {
  it("renders correctly with 0 findings", () => {
    render(<SeveritySummary findings={[]} />);
    // Initial display might just show bars with 0% width, but let's check basic text
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getByText("Medium")).toBeInTheDocument();
    expect(screen.getByText("Low")).toBeInTheDocument();
    expect(screen.getByText("Info")).toBeInTheDocument();
    
    // There should be five '0' badges
    const zeroBadges = screen.getAllByText("0");
    expect(zeroBadges.length).toBeGreaterThanOrEqual(5);
  });

  it("calculates severities correctly", () => {
    const findings = [
      { tool: "test", phase: "test", target: "test", title: "1", detail: "", cvss: 9.8, severity: "Critical" },
      { tool: "test", phase: "test", target: "test", title: "2", detail: "", cvss: 9.0, severity: "Critical" },
      { tool: "test", phase: "test", target: "test", title: "3", detail: "", cvss: 7.5, severity: "High" },
      { tool: "test", phase: "test", target: "test", title: "4", detail: "", severity: "Low" },
      { tool: "test", phase: "test", target: "test", title: "5", detail: "", severity: "Low" }
    ];

    render(<SeveritySummary findings={findings} />);
    
    // Critical: 2
    // High: 1
    // Medium: 0
    // Low: 2
    // Info: 0
    
    // Test the textual counts next to the labels. Note: The DOM has multiple text nodes, 
    // but the simplest check is asserting the exact counts exist in the document near the bars.
    expect(screen.getAllByText("2")).toHaveLength(2); // Critical & Low
    expect(screen.getByText("1")).toBeInTheDocument(); // High
  });
});
