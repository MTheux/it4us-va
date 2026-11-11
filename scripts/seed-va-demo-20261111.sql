-- IT4US VA demo data. Synthetic only; no scanner execution or authorization.
-- Idempotent. Run with psql -v ON_ERROR_STOP=1 -1.
DO $demo$
DECLARE
  demo_company bigint;
  demo_task bigint;
  demo_exploration bigint;
  ip_a bigint;
  ip_b bigint;
  ip_c bigint;
  service_smb bigint;
  service_tls bigint;
  service_ssh bigint;
  service_pg bigint;
BEGIN
  INSERT INTO companies(name, nkey)
  VALUES ('[DEMO] Infraestrutura ficticia', 'demo-infra-va-20261111')
  ON CONFLICT (nkey) DO NOTHING;
  SELECT id INTO STRICT demo_company FROM companies WHERE nkey = 'demo-infra-va-20261111';

  IF EXISTS (
    SELECT 1 FROM assets
    WHERE ip IN ('192.0.2.10','198.51.100.20','203.0.113.30')
      AND NOT (company_id=demo_company AND extra @> '{"demo":true,"synthetic":true}'::jsonb)
  ) THEN
    RAISE EXCEPTION 'Documentation IP already belongs to non-demo data; choose another environment';
  END IF;

  SELECT id INTO demo_task FROM tasks WHERE name = 'DEMO - VA Infra (dados ficticios)' AND deleted_at IS NULL LIMIT 1;
  IF demo_task IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM tasks WHERE id=demo_task AND company_id=demo_company
      AND description LIKE 'Ambiente ficticio para visualizar ativos e achados.%'
  ) THEN
    RAISE EXCEPTION 'Demo task name is already used by non-demo data';
  END IF;
  IF demo_task IS NULL THEN
    INSERT INTO explorations(description, goal)
    VALUES ('DEMO: inventario e achados de infraestrutura inteiramente ficticios.',
            'Visualizar o fluxo de triagem sem executar scanner.')
    RETURNING id INTO demo_exploration;
    INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
    VALUES (demo_exploration, 'fact', '{"summary":"DEMO: nenhum teste real foi executado"}'::jsonb,
            0, 'origin', 'system');
    INSERT INTO tasks(name, description, goal, exploration_id, company_id, status)
    VALUES ('DEMO - VA Infra (dados ficticios)',
            'Ambiente ficticio para visualizar ativos e achados. IPs RFC 5737; nenhum scan executado.',
            'Visualizar o fluxo de discovery, VA aprofundado e triagem sem trafego de rede.',
            demo_exploration, demo_company, 'created')
    RETURNING id INTO demo_task;
  END IF;

  INSERT INTO assets(type, company_id, task_ids, ip, c_segment, open_ports, extra)
  VALUES ('ip', demo_company, ARRAY[demo_task], '192.0.2.10', '192.0.2.0/24',
          ARRAY['{"port":22,"service":"ssh"}'::jsonb, '{"port":445,"service":"smb"}'::jsonb],
          '{"demo":true,"synthetic":true}'::jsonb)
  ON CONFLICT DO NOTHING;
  SELECT id INTO STRICT ip_a FROM assets WHERE type='ip' AND ip='192.0.2.10';

  INSERT INTO assets(type, company_id, task_ids, ip, c_segment, open_ports, extra)
  VALUES ('ip', demo_company, ARRAY[demo_task], '198.51.100.20', '198.51.100.0/24',
          ARRAY['{"port":443,"service":"tls"}'::jsonb],
          '{"demo":true,"synthetic":true}'::jsonb)
  ON CONFLICT DO NOTHING;
  SELECT id INTO STRICT ip_b FROM assets WHERE type='ip' AND ip='198.51.100.20';

  INSERT INTO assets(type, company_id, task_ids, ip, c_segment, open_ports, extra)
  VALUES ('ip', demo_company, ARRAY[demo_task], '203.0.113.30', '203.0.113.0/24',
          ARRAY['{"port":22,"service":"ssh"}'::jsonb, '{"port":5432,"service":"postgresql"}'::jsonb],
          '{"demo":true,"synthetic":true}'::jsonb)
  ON CONFLICT DO NOTHING;
  SELECT id INTO STRICT ip_c FROM assets WHERE type='ip' AND ip='203.0.113.30';

  INSERT INTO assets(type, company_id, task_ids, service_type, service_name, ip, port, extra)
  VALUES ('service', demo_company, ARRAY[demo_task], 'other', 'SMB', '192.0.2.10', 445,
          '{"demo":true,"synthetic":true}'::jsonb)
  ON CONFLICT DO NOTHING;
  SELECT id INTO STRICT service_smb FROM assets WHERE type='service' AND service_type='other' AND ip='192.0.2.10' AND port=445 AND service_name='SMB';

  INSERT INTO assets(type, company_id, task_ids, service_type, service_name, ip, port, extra)
  VALUES ('service', demo_company, ARRAY[demo_task], 'other', 'TLS', '198.51.100.20', 443,
          '{"demo":true,"synthetic":true}'::jsonb)
  ON CONFLICT DO NOTHING;
  SELECT id INTO STRICT service_tls FROM assets WHERE type='service' AND service_type='other' AND ip='198.51.100.20' AND port=443 AND service_name='TLS';

  INSERT INTO assets(type, company_id, task_ids, service_type, service_name, ip, port, extra)
  VALUES ('service', demo_company, ARRAY[demo_task], 'other', 'SSH', '203.0.113.30', 22,
          '{"demo":true,"synthetic":true}'::jsonb)
  ON CONFLICT DO NOTHING;
  SELECT id INTO STRICT service_ssh FROM assets WHERE type='service' AND service_type='other' AND ip='203.0.113.30' AND port=22 AND service_name='SSH';

  INSERT INTO assets(type, company_id, task_ids, service_type, service_name, ip, port, extra)
  VALUES ('service', demo_company, ARRAY[demo_task], 'other', 'PostgreSQL', '203.0.113.30', 5432,
          '{"demo":true,"synthetic":true}'::jsonb)
  ON CONFLICT DO NOTHING;
  SELECT id INTO STRICT service_pg FROM assets WHERE type='service' AND service_type='other' AND ip='203.0.113.30' AND port=5432 AND service_name='PostgreSQL';

  INSERT INTO findings(task_id, vulnclass, name, severity, summary, evidence, worker, asset_ids, status)
  SELECT demo_task, 'smb-assinatura-opcional', '[DEMO] Assinatura SMB nao obrigatoria', 'medium',
         'Exemplo ficticio de candidato de configuracao SMB; requer validacao humana.',
         'DADO FICTICIO. Nenhuma resposta SMB foi coletada e nenhum teste foi executado.',
         'demo:synthetic', jsonb_build_array(ip_a, service_smb), 'pending'
  WHERE NOT EXISTS (SELECT 1 FROM findings WHERE task_id=demo_task AND worker='demo:synthetic' AND name='[DEMO] Assinatura SMB nao obrigatoria');

  INSERT INTO findings(task_id, vulnclass, name, severity, summary, evidence, worker, asset_ids, status)
  SELECT demo_task, 'tls-certificado-expirado', '[DEMO] Certificado TLS expirado', 'medium',
         'Exemplo ficticio de candidato de PKI; data e cadeia precisam ser verificadas em ambiente autorizado.',
         'DADO FICTICIO. Nenhum certificado foi obtido; a data de expiracao e apenas ilustrativa.',
         'demo:synthetic', jsonb_build_array(ip_b, service_tls), 'pending'
  WHERE NOT EXISTS (SELECT 1 FROM findings WHERE task_id=demo_task AND worker='demo:synthetic' AND name='[DEMO] Certificado TLS expirado');

  INSERT INTO findings(task_id, vulnclass, name, severity, summary, evidence, worker, asset_ids, status)
  SELECT demo_task, 'ssh-configuracao', '[DEMO] Algoritmo SSH legado', 'low',
         'Exemplo ficticio para visualizar priorizacao e triagem de configuracao SSH.',
         'DADO FICTICIO. Nenhum handshake SSH foi realizado.',
         'demo:synthetic', jsonb_build_array(ip_c, service_ssh), 'pending'
  WHERE NOT EXISTS (SELECT 1 FROM findings WHERE task_id=demo_task AND worker='demo:synthetic' AND name='[DEMO] Algoritmo SSH legado');

  INSERT INTO findings(task_id, vulnclass, name, severity, summary, evidence, worker, asset_ids, status)
  SELECT demo_task, 'exposicao-de-servico', '[DEMO] PostgreSQL exposto na rede', 'high',
         'Exemplo ficticio de servico de dados exposto; impacto depende de rota, autenticacao e segmentacao.',
         'DADO FICTICIO. Porta e servico foram inseridos para demonstracao; nao houve discovery.',
         'demo:synthetic', jsonb_build_array(ip_c, service_pg), 'pending'
  WHERE NOT EXISTS (SELECT 1 FROM findings WHERE task_id=demo_task AND worker='demo:synthetic' AND name='[DEMO] PostgreSQL exposto na rede');
END
$demo$;
