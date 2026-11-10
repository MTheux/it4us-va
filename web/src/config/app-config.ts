import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "IT4US VA",
  version: packageJson.version,
  copyright: `© ${currentYear}, IT4US VA.`,
  meta: {
    title: "IT4US VA — Console de Avaliação de Vulnerabilidade",
    description: "Console de avaliação de vulnerabilidade (VA) guiado por IA",
  },
};
