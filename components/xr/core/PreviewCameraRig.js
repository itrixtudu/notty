import { useEffect, useRef } from 'react';
import { useFrame, useThree } from '@react-three/fiber';
import { useXR } from '@react-three/xr';
import { Euler, Vector3 } from 'three';
import useSpatialStore from '../../../lib/stores/spatialStore.js';

const DEFAULT_CAMERA_POSITION = new Vector3(0, 1.6, 4);
const DEFAULT_LOOK_AT = new Vector3(0, 1.4, 0);
const DEFAULT_TERMINAL_POSITION = new Vector3(0, 1.4, -1.6);
const UP_AXIS = new Vector3(0, 1, 0);

function vectorFromArray(value, fallback) {
  if (!Array.isArray(value) || value.length < 3) {
    return fallback.clone();
  }

  const x = Number.isFinite(value[0]) ? value[0] : fallback.x;
  const y = Number.isFinite(value[1]) ? value[1] : fallback.y;
  const z = Number.isFinite(value[2]) ? value[2] : fallback.z;

  return new Vector3(x, y, z);
}

function computeCameraTarget(terminal) {
  const position = vectorFromArray(terminal?.position, DEFAULT_TERMINAL_POSITION);
  const rotation = Array.isArray(terminal?.rotation)
    ? new Euler(
        Number.isFinite(terminal.rotation[0]) ? terminal.rotation[0] : 0,
        Number.isFinite(terminal.rotation[1]) ? terminal.rotation[1] : 0,
        Number.isFinite(terminal.rotation[2]) ? terminal.rotation[2] : 0,
        'XYZ'
      )
    : new Euler();
  const scale = Array.isArray(terminal?.scale) ? terminal.scale : [1, 1, 1];
  const forward = new Vector3(0, 0, 1).applyEuler(rotation).normalize();
  const up = UP_AXIS.clone().applyEuler(rotation).normalize();
  const sizeFactor = Math.max(scale[0] ?? 1, scale[1] ?? 1);
  const distance = 1.4 + sizeFactor * 0.65;
  const viewPosition = position.clone().add(forward.clone().multiplyScalar(distance));
  viewPosition.y += 0.18 * (scale[1] ?? 1);
  const lookAt = position.clone().add(up.multiplyScalar(0.12));

  return { position: viewPosition, lookAt };
}

export default function PreviewCameraRig() {
  const { camera } = useThree();
  const { isPresenting } = useXR();
  const activeTerminal = useSpatialStore((state) =>
    state.activeTerminalId ? state.terminals[state.activeTerminalId] ?? null : null
  );

  const targetPosition = useRef(DEFAULT_CAMERA_POSITION.clone());
  const targetLookAt = useRef(DEFAULT_LOOK_AT.clone());
  const currentLookAt = useRef(DEFAULT_LOOK_AT.clone());

  useEffect(() => {
    camera.position.copy(DEFAULT_CAMERA_POSITION);
    camera.lookAt(DEFAULT_LOOK_AT);
    currentLookAt.current.copy(DEFAULT_LOOK_AT);
  }, [camera]);

  useEffect(() => {
    if (isPresenting) {
      return;
    }

    if (activeTerminal) {
      const target = computeCameraTarget(activeTerminal);
      targetPosition.current.copy(target.position);
      targetLookAt.current.copy(target.lookAt);
    } else {
      targetPosition.current.copy(DEFAULT_CAMERA_POSITION);
      targetLookAt.current.copy(DEFAULT_LOOK_AT);
    }
  }, [activeTerminal, isPresenting]);

  useEffect(() => {
    if (isPresenting) {
      return;
    }

    camera.position.lerp(targetPosition.current, 1);
    currentLookAt.current.copy(targetLookAt.current);
    camera.lookAt(currentLookAt.current);
  }, [camera, isPresenting]);

  useFrame((_, delta) => {
    if (isPresenting) {
      return;
    }

    const smoothing = 1 - Math.exp(-delta * 4.5);
    camera.position.lerp(targetPosition.current, smoothing);
    currentLookAt.current.lerp(targetLookAt.current, smoothing);
    camera.lookAt(currentLookAt.current);
  });

  return null;
}
