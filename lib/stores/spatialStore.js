import { create } from 'zustand';

const defaultPreferences = {
  snapToGrid: true,
  gridSize: 0.25,
  rotationSnap: Math.PI / 12,
  showBounds: true
};

const defaultLayoutPresets = {
  single: {
    label: 'Single Terminal',
    placements: [
      {
        id: 'primary',
        position: [0, 1.4, -1.6],
        rotation: [0, 0, 0],
        scale: [1, 1, 1]
      }
    ]
  },
  arc: {
    label: 'Three Terminal Arc',
    placements: [
      {
        id: 'primary',
        position: [0, 1.45, -1.7],
        rotation: [0, 0, 0],
        scale: [1, 1, 1]
      },
      {
        id: 'secondary',
        position: [-0.9, 1.35, -1.6],
        rotation: [0, 0.25, 0],
        scale: [1, 1, 1]
      },
      {
        id: 'tertiary',
        position: [0.9, 1.35, -1.6],
        rotation: [0, -0.25, 0],
        scale: [1, 1, 1]
      }
    ]
  }
};

const snapValue = (value, step) => Math.round(value / step) * step;

const normalizePose = (pose = {}) => ({
  position: pose.position ?? [0, 1.4, -1.6],
  rotation: pose.rotation ?? [0, 0, 0],
  scale: pose.scale ?? [1, 1, 1]
});

const applyGridSnap = (pose, gridSize) => {
  if (!pose.position) {
    return pose;
  }

  return {
    ...pose,
    position: pose.position.map(value => snapValue(value, gridSize))
  };
};

const useSpatialStore = create((set, get) => ({
  terminals: {},
  activeTerminalId: null,
  grabbedTerminalId: null,
  handTracking: {
    left: null,
    right: null
  },
  userPreferences: { ...defaultPreferences },
  layoutPresets: { ...defaultLayoutPresets },
  activeLayoutPreset: 'single',
  registerTerminal: (id, pose = {}) =>
    set(state => ({
      terminals: {
        ...state.terminals,
        [id]: {
          id,
          ...normalizePose(pose)
        }
      }
    })),
  unregisterTerminal: id =>
    set(state => {
      if (!state.terminals[id]) {
        return {};
      }

      const terminals = { ...state.terminals };
      delete terminals[id];

      return {
        terminals,
        activeTerminalId: state.activeTerminalId === id ? null : state.activeTerminalId,
        grabbedTerminalId: state.grabbedTerminalId === id ? null : state.grabbedTerminalId
      };
    }),
  setTerminalPose: (id, pose, options = { respectSnap: true }) =>
    set(state => {
      const current = state.terminals[id];

      if (!current) {
        return {};
      }

      const preferences = get().userPreferences;
      const shouldSnap = options?.respectSnap !== false && preferences.snapToGrid;
      const targetPose = normalizePose({
        position: pose?.position ?? current.position,
        rotation: pose?.rotation ?? current.rotation,
        scale: pose?.scale ?? current.scale
      });

      const nextPose = shouldSnap
        ? applyGridSnap(targetPose, preferences.gridSize)
        : targetPose;

      return {
        terminals: {
          ...state.terminals,
          [id]: {
            ...current,
            ...nextPose
          }
        }
      };
    }),
  setActiveTerminal: id => set({ activeTerminalId: id }),
  setGrabbedTerminal: id => set({ grabbedTerminalId: id }),
  clearGrabbedTerminal: () => set({ grabbedTerminalId: null }),
  updateHandTracking: (hand, data) =>
    set(state => ({
      handTracking: {
        ...state.handTracking,
        [hand]: data
      }
    })),
  resetHandTracking: () => set({ handTracking: { left: null, right: null } }),
  setUserPreference: (key, value) =>
    set(state => ({
      userPreferences: {
        ...state.userPreferences,
        [key]: value
      }
    })),
  hydratePreferences: preferences =>
    set(state => ({
      userPreferences: {
        ...state.userPreferences,
        ...preferences
      }
    })),
  saveLayoutPreset: (name, preset) =>
    set(state => ({
      layoutPresets: {
        ...state.layoutPresets,
        [name]: {
          label: preset.label ?? name,
          placements: preset.placements ?? []
        }
      }
    })),
  applyLayoutPreset: name =>
    set(state => {
      const preset = state.layoutPresets[name];

      if (!preset) {
        return {};
      }

      const terminals = { ...state.terminals };

      preset.placements.forEach(placement => {
        if (!placement.id || !terminals[placement.id]) {
          return;
        }

        terminals[placement.id] = {
          ...terminals[placement.id],
          position: placement.position ?? terminals[placement.id].position,
          rotation: placement.rotation ?? terminals[placement.id].rotation,
          scale: placement.scale ?? terminals[placement.id].scale
        };
      });

      return {
        terminals,
        activeLayoutPreset: name
      };
    }),
  setActiveLayoutPreset: name => set({ activeLayoutPreset: name }),
  resetLayout: () =>
    set(state => {
      const preset = state.layoutPresets.single ?? defaultLayoutPresets.single;

      if (!preset) {
        return {};
      }

      const terminals = { ...state.terminals };

      preset.placements.forEach(placement => {
        if (!placement.id || !terminals[placement.id]) {
          return;
        }

        terminals[placement.id] = {
          ...terminals[placement.id],
          position: placement.position ?? terminals[placement.id].position,
          rotation: placement.rotation ?? terminals[placement.id].rotation,
          scale: placement.scale ?? terminals[placement.id].scale
        };
      });

      return {
        terminals,
        activeLayoutPreset: 'single'
      };
    })
}));

export default useSpatialStore;
export { defaultLayoutPresets, defaultPreferences };
