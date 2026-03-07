// src/services/socialProvider.js
const SUPPORTED_PROVIDERS = [
  'google', 'facebook', 'twitter', 'github',
  'apple', 'linkedin', 'microsoft', 'discord',
];

const PROVIDER_DISPLAY_NAMES = {
  google:    'Google',
  facebook:  'Facebook',
  twitter:   'Twitter/X',
  github:    'GitHub',
  apple:     'Apple',
  linkedin:  'LinkedIn',
  microsoft: 'Microsoft',
  discord:   'Discord',
};

const isSupportedProvider = (provider) =>
  SUPPORTED_PROVIDERS.includes(provider?.toLowerCase());

module.exports = { SUPPORTED_PROVIDERS, PROVIDER_DISPLAY_NAMES, isSupportedProvider };
