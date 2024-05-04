import { tokenizedAuth } from './tokenized-auth';

describe('tokenizedAuth', () => {
  it('should work', () => {
    expect(tokenizedAuth()).toEqual('tokenized-auth');
  });
});
