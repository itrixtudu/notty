import { Suspense } from 'react';
import { Canvas } from '@react-three/fiber';
import { XR } from '@react-three/xr';
import PreviewCameraRig from './PreviewCameraRig.js';

const fallbackScene = (
  <group>
    <ambientLight intensity={0.6} />
    <directionalLight position={[5, 10, 2]} intensity={1.2} castShadow />
    <mesh rotation={[-Math.PI / 2, 0, 0]} receiveShadow>
      <planeGeometry args={[20, 20]} />
      <meshStandardMaterial color="#151a2d" />
    </mesh>
  </group>
);

const BaseXRCanvas = ({ children, mode = 'vr', store, ...rest }) => {
  const content = children ?? fallbackScene;

  if (!store) {
    return null;
  }

  return (
    <Canvas
      shadows
      dpr={[1, 1.5]}
      camera={{ fov: 70, position: [0, 1.6, 4] }}
      gl={{ antialias: true, alpha: false }}
      {...rest}
    >
      <color attach="background" args={[mode === 'ar' ? '#00000000' : '#05070f']} />
      <Suspense fallback={null}>
        <XR store={store}>
          <PreviewCameraRig />
          {content}
        </XR>
      </Suspense>
    </Canvas>
  );
};

export default BaseXRCanvas;
