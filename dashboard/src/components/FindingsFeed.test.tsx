import { render, screen } from "@testing-library/react";
import { FindingsFeed } from "./FindingsFeed";

describe("FindingsFeed", () => {
  it("renders empty state correctly", () => {
    render(<FindingsFeed findings={[]} />);
    expect(screen.getByText("No findings yet. Launch an engagement.")).toBeInTheDocument();
    expect(screen.getByText("0")).toBeInTheDocument(); // Count badge
  });

  it("renders findings and skips out-of-scope/no findings", () => {
    const findings = [
      { tool: "nmap", phase: "recon", target: "127.0.0.1", title: "Open port 80", detail: "HTTP" },
      { tool: "nikto", phase: "scanning", target: "127.0.0.1", title: "Out of scope", detail: "Ignored" },
      { tool: "nuclei", phase: "scanning", target: "127.0.0.1", title: "No findings", detail: "Ignored" }
    ];
    
    render(<FindingsFeed findings={findings} />);
    
    // Should only show the first one
    expect(screen.getByText("1")).toBeInTheDocument();
    expect(screen.getByText("Open port 80")).toBeInTheDocument();
    expect(screen.queryByText("Out of scope")).not.toBeInTheDocument();
  });
});
