-- Removes only records owned by the synthetic VA demo marker.
-- Review first if the demo task was edited to contain real data.
DO $demo$
DECLARE
  demo_task bigint;
  demo_exploration bigint;
  demo_company bigint;
BEGIN
  SELECT id, exploration_id INTO demo_task, demo_exploration
  FROM tasks WHERE name='DEMO - VA Infra (dados ficticios)' AND deleted_at IS NULL LIMIT 1;
  SELECT id INTO demo_company FROM companies WHERE nkey='demo-infra-va-20261111';
  IF demo_task IS NULL OR demo_company IS NULL THEN RETURN; END IF;
  IF EXISTS (SELECT 1 FROM assets WHERE company_id=demo_company AND NOT COALESCE((extra->>'demo')::boolean,false))
     OR EXISTS (SELECT 1 FROM assets WHERE demo_task=ANY(task_ids) AND company_id IS DISTINCT FROM demo_company)
     OR EXISTS (SELECT 1 FROM findings WHERE task_id=demo_task AND worker<>'demo:synthetic') THEN
    RAISE EXCEPTION 'Demo was mixed with non-demo data; manual review required';
  END IF;
  DELETE FROM findings WHERE task_id=demo_task AND worker='demo:synthetic';
  DELETE FROM assets WHERE company_id=demo_company AND COALESCE((extra->>'demo')::boolean,false);
  DELETE FROM tasks WHERE id=demo_task;
  DELETE FROM explorations WHERE id=demo_exploration;
  DELETE FROM companies WHERE id=demo_company;
END
$demo$;
