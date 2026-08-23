import Head from 'next/head';
import TerminalConsole from '../components/TerminalConsole.js';
import { isTerminalLockdownEnabled } from '../lib/lockdown.js';

export default function LockdownPage({ sessionId }) {
  return (
    <main className="lockdown-page">
      <Head>
        <title>Notty Lockdown</title>
      </Head>

      <div className="lockdown-terminal">
        <TerminalConsole
          sessionId={sessionId}
          fullViewport
          showPlaceholder={false}
          showChrome={false}
        />
      </div>
    </main>
  );
}

export async function getServerSideProps() {
  const enabled = isTerminalLockdownEnabled()
    || isTerminalLockdownEnabled(process.env.NOTTY_LOCKDOWN_UI ?? '');
  const sessionId = process.env.NOTTY_LOCKDOWN_SESSION_ID || '1';

  if (!enabled) {
    return {
      redirect: {
        destination: '/',
        permanent: false
      }
    };
  }

  return {
    props: {
      sessionId
    }
  };
}
