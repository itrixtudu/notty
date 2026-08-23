import dynamic from 'next/dynamic';
import Head from 'next/head';

const XRWorkspace = dynamic(() => import('../components/xr/XRWorkspace'), {
  ssr: false
});

export default function XRPage() {
  return (
    <>
      <Head>
        <title>Spatial XR Workspace · notty</title>
        <meta
          name="description"
          content="Browse your terminal sessions and launch immersive XR workspaces with WebXR-enabled devices."
        />
      </Head>
      <XRWorkspace />
    </>
  );
}
