import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { afterEach, expect, it } from 'vitest';
import { PasswordInput } from './ui';

afterEach(cleanup);

function Harness() {
  const [v, setV] = useState('');
  return <><label htmlFor="pw">Password</label><PasswordInput id="pw" value={v} onChange={setV} /><output>{v}</output></>;
}

it('hides the password by default and toggles visibility with the eye button', () => {
  render(<Harness />);
  const input = screen.getByLabelText('Password') as HTMLInputElement;
  expect(input.type).toBe('password');
  fireEvent.change(input, { target: { value: 'Secret-Passw0rd!' } });
  const show = screen.getByRole('button', { name: 'Show password' });
  expect(show.getAttribute('aria-pressed')).toBe('false');
  fireEvent.click(show);
  expect(input.type).toBe('text');
  expect(input.value).toBe('Secret-Passw0rd!');  // toggling never changes what was typed
  const hide = screen.getByRole('button', { name: 'Hide password' });
  expect(hide.getAttribute('aria-pressed')).toBe('true');
  fireEvent.click(hide);
  expect(input.type).toBe('password');
});

it('the eye button does not submit the surrounding form', () => {
  let submitted = false;
  render(<form onSubmit={(e) => { e.preventDefault(); submitted = true; }}><PasswordInput id="p" value="" onChange={() => {}} /></form>);
  fireEvent.click(screen.getByRole('button', { name: 'Show password' }));
  expect(submitted).toBe(false);
});
