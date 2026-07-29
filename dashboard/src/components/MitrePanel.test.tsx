import { render, screen } from "@testing-library/react";
import { MitrePanel } from "./MitrePanel";

describe("MitrePanel", () => {
  it("renders empty state correctly", () => {
    render(<MitrePanel findings={[]} />);
    expect(screen.getByText("No MITRE tactics found.")).toBeInTheDocument();
    expect(screen.getByText("0")).toBeInTheDocument();
  });

  it("extracts, deduplicates, and sorts MITRE codes", () => {
    const findings = [
      { tool: "test", phase: "test", target: "test", title: "test", detail: "test", mitre: "T1190" },
      { tool: "test", phase: "test", target: "test", title: "test", detail: "test", mitre: "T1046" },
      { tool: "test", phase: "test", target: "test", title: "test", detail: "test", mitre: "T1190" }, // duplicate
      { tool: "test", phase: "test", target: "test", title: "test", detail: "test" } // missing mitre
    ];

    render(<MitrePanel findings={findings} />);
    
    expect(screen.getByText("2")).toBeInTheDocument(); // Count is 2
    
    // T1046 should come first alphabetically
    const badges = screen.getAllByText(/^T1\d{3}$/);
    expect(badges.length).toBe(2);
    expect(badges[0]).toHaveTextContent("T1046");
    expect(badges[1]).toHaveTextContent("T1190");
  });
});
