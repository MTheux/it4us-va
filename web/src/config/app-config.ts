import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "Draxen",
  version: packageJson.version,
  copyright: `© ${currentYear}, Draxen.`,
  meta: {
    title: "Draxen — Console de Pentest Autônomo",
    description: "Console do sistema de pentest autônomo guiado por LLM",
  },
};
