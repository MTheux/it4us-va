import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "Guard4US",
  version: packageJson.version,
  copyright: `© ${currentYear}, IT4US · Guard4US.`,
  meta: {
    title: "Guard4US — Avaliação de Vulnerabilidades",
    description: "Console de avaliação de vulnerabilidades em infraestrutura da IT4US",
  },
};
