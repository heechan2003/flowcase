-- Record what each published day put in scope, and what it left out.
--
-- The support gate decided which addresses had a behavioural day, and nothing counted what it
-- excluded: `staged_client_rows` is every observed address, not the supported population. Under
-- the definition in force those two numbers are within 0.02% of each other, which is exactly the
-- defect — the gate admits essentially everything, and no published day recorded that it did.
--
-- `population_definition_version` is here so a day-over-day comparison can tell whether it spans a
-- change of definition. Comparing a supported population across two different definitions measures
-- the definition, not the population.
--
-- Strictly additive. Rows published before this migration keep NULL, which reads as "published
-- before the census existed"; those days cannot be re-derived, because source detail expires in
-- roughly fifteen days.
ALTER TABLE ops.pipeline_run ADD COLUMN supported_client_rows UBIGINT;
ALTER TABLE ops.pipeline_run ADD COLUMN out_of_scope_client_rows UBIGINT;
ALTER TABLE ops.pipeline_run ADD COLUMN population_definition_version VARCHAR;
