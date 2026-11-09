import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { CheckList, DecisionBadge, short } from '../../src/components/ui';
import { SimulatedBanner } from '../../src/components/SimulatedBanner';

describe('UI components', () => {
  it('labels unsupported checks as "not in circuit", never as pass', () => {
    render(
      <CheckList
        checks={[
          { id: 'nonce', label: 'Proof bound to challenge nonce', status: 'not-supported' },
          { id: 'g', label: 'Groth16', status: 'pass' },
        ]}
      />,
    );
    expect(screen.getByText('not in circuit')).toBeInTheDocument();
    expect(screen.getByLabelText('not supported')).toBeInTheDocument();
    expect(screen.getAllByText('pass')).toHaveLength(1);
  });
  it('renders decisions distinctly', () => {
    render(
      <>
        <DecisionBadge decision="granted" />
        <DecisionBadge decision="blocked" />
        <DecisionBadge decision="denied" />
      </>,
    );
    expect(screen.getByText('Granted')).toBeInTheDocument();
    expect(screen.getByText('Blocked')).toBeInTheDocument();
    expect(screen.getByText('Denied')).toBeInTheDocument();
  });
  it('the simulation banner states it is not evidence of security', () => {
    render(<SimulatedBanner />);
    expect(screen.getByRole('status')).toHaveTextContent(/not evidence of security/);
  });
  it('shortens long field elements', () => {
    expect(short('1234567890123456789', 4)).toBe('1234…6789');
  });
});
