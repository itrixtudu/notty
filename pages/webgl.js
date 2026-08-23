import dynamic from 'next/dynamic';
import Head from 'next/head';

const WebGLWorkspace = dynamic(() => import('../components/webgl/WebGLWorkspace'), {
  ssr: false
});

export default function WebGLPage() {
  return (
    <>
      <Head>
        <title>Immersive WebGL Terminals · notty</title>
        <meta
          name="description"
          content="Explore your terminal sessions within a fully spatial WebGL carousel without relying on DOM overlays."
        />
      </Head>
      <WebGLWorkspace />
    </>
  );
}
