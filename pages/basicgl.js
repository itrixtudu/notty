import dynamic from 'next/dynamic';
import Head from 'next/head';

const BasicGLViewer = dynamic(() => import('../components/basicgl/BasicGLViewer.js'), {
  ssr: false,
  loading: () => (
    <div style={{ padding: '2rem', fontFamily: 'system-ui, sans-serif' }}>
      Loading WebGL…
    </div>
  )
});

export default function BasicGLPage() {
  return (
    <>
      <Head>
        <title>Basic WebGL Terminal · notty</title>
        <meta name="description" content="Minimal WebGL textured terminal viewer." />
      </Head>
      <BasicGLViewer sessionId={1} />
    </>
  );
}

