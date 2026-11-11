const stages = [
  ["01", "Ativos", "Defina o ambiente e o escopo da avaliação."],
  ["02", "Campanha", "Execute verificações de infraestrutura autorizadas."],
  ["03", "Agente", "Investigue candidatos com contexto e evidências."],
  ["04", "Revisão", "Confirme os achados antes de encaminhar correções."],
] as const;

export function BrandProof() {
  return (
    <aside className="proof hidden flex-col p-10 text-left lg:flex lg:w-1/2 xl:p-14" aria-label="IT4US VA">
      <div className="proof-grid" aria-hidden="true" />
      <div className="relative flex h-full flex-col">
        {/* The artwork is the existing IT4US Cyber Security brand asset. */}
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src="/brand/it4us-logo-dark.png"
          alt="IT4US Cyber Security"
          width={600}
          height={260}
          className="proof-brand h-auto w-52 object-contain object-left xl:w-64"
        />

        <div className="my-auto max-w-xl py-10">
          <div className="proof-kicker">IT4US VA · VULNERABILITY ASSESSMENT</div>
          <h1 className="proof-title mt-5">Visibilidade para agir.</h1>
          <p className="proof-copy mt-5">
            Descubra ativos, conduza campanhas de avaliação e revise evidências com apoio de agentes.
          </p>
          <div className="proof-flow mt-10" aria-label="Fluxo da avaliação">
            {stages.map(([number, title, description]) => (
              <div className="proof-stage" key={number}>
                <span className="proof-stage-number">{number}</span>
                <div>
                  <strong>{title}</strong>
                  <p>{description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <p className="proof-bottom">Da descoberta à decisão, com o SOC no controle.</p>
      </div>
    </aside>
  );
}
