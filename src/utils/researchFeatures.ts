type ResearchFeaturesState = {
  enabled: boolean;
};

const state: ResearchFeaturesState = {
  enabled: import.meta.env.VITE_ENABLE_RESEARCH_FEATURES === 'true'
};

export function isResearchFeaturesEnabled(): boolean {
  return state.enabled;
}

export function setResearchFeaturesEnabled(enabled: boolean): void {
  state.enabled = enabled === true;
}

export function getResearchFeaturesState(): ResearchFeaturesState {
  return { ...state };
}
