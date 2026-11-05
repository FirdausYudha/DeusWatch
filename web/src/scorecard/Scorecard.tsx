import { useEffect, useState } from 'react'
import {
  fetchScorecard,
  importScenarioRuns,
  addScorecardInput,
  can,
  type Scorecard as ScorecardData,
  type ScorecardIndicator,
  type Me,
} from '../lib/api'
import { Button, Card, EmptyState, ErrorText, Input, Page, PageHeader, Pill, Select } from '../components/ui'

// CSF functions in the order the scorecard groups them.
const CSF_ORDER = ['Identify', 'Protect', 'Detect', 'Respond', 'Govern']

function predicateClass(pred: string): string {
  if (pred === 'Effective') return 'bg-success/15 text-success'
  if (pred === 'Adequate') return 'bg-medium/15 text-medium'
  if (pred === 'Needs Improvement') return 'bg-critical/15 text-critical'
  return 'bg-info/15 text-muted'
}

function PredicateBadge({ pred }: { pred: string }) {
  if (!pred) return <span className="text-muted text-sm">no data yet</span>
  return <Pill className={predicateClass(pred)}>{pred}</Pill>
}

function formatValue(ind: ScorecardIndicator): string {
  if (ind.value === null) return 'no data yet'
  const v = Math.round(ind.value * 10) / 10
  return ind.unit ? `${v} ${ind.unit}` : `${v}`
}

export default function Scorecard({ me }: { me: Me }) {
  const canManage = can(me, 'manage_settings')
  const [data, setData] = useState<ScorecardData | null>(null)
  const [days, setDays] = useState(30)
  const [error, setError] = useState('')
  const [loaded, setLoaded] = useState(false)

  const [csv, setCsv] = useState('')
  const [importMsg, setImportMsg] = useState('')
  const [prepDays, setPrepDays] = useState('')
  const [inputMsg, setInputMsg] = useState('')

  const load = () =>
    fetchScorecard(days)
      .then(setData)
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoaded(true))

  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [days])

  const doImport = async () => {
    setImportMsg('')
    setError('')
    try {
      const res = await importScenarioRuns(csv)
      setImportMsg(
        `${res.imported} rows imported` +
          (res.rejected.length ? `, ${res.rejected.length} rejected: ${res.rejected.join('; ')}` : ''),
      )
      await load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const savePrep = async () => {
    setInputMsg('')
    setError('')
    const v = parseFloat(prepDays)
    if (isNaN(v)) {
      setError('enter the report preparation time as a number (days)')
      return
    }
    try {
      await addScorecardInput('report_prep_time', v)
      setInputMsg('saved')
      setPrepDays('')
      await load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <Page>
      <PageHeader
        subtitle="Eight security indicators for the selected period, each with a predicate and an overall one, grouped by NIST CSF function."
        actions={
          <Select value={days} onChange={(e) => setDays(Number(e.target.value))}>
            <option value={7}>7 days</option>
            <option value={30}>30 days</option>
            <option value={90}>90 days</option>
          </Select>
        }
      />

      <div className="grid gap-4">
      {error && <ErrorText>{error}</ErrorText>}

      {!loaded && !error && (
        <Card title="Loading">
          <div className="text-muted text-sm">Computing indicators…</div>
        </Card>
      )}

      {data && (
        <Card title="Overall predicate">
          <div className="flex items-center gap-4">
            <PredicateBadge pred={data.overall_predicate} />
            <span className="text-muted text-sm">
              {data.overall_score !== null
                ? `average score ${Math.round(data.overall_score * 100) / 100} across ${data.indicators_counted} of ${data.indicators_total} indicators`
                : `no indicators could be computed yet (0 of ${data.indicators_total})`}
            </span>
          </div>
        </Card>
      )}

      {data &&
        CSF_ORDER.filter((csf) => data.indicators.some((i) => i.csf_function === csf)).map((csf) => (
          <Card key={csf} title={csf}>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-muted text-left">
                  <th className="py-1 font-medium">Indicator</th>
                  <th className="py-1 font-medium">Value</th>
                  <th className="py-1 font-medium">Predicate</th>
                  <th className="py-1 font-medium">Note</th>
                </tr>
              </thead>
              <tbody>
                {data.indicators
                  .filter((i) => i.csf_function === csf)
                  .map((i) => (
                    <tr key={i.key} className="border-t border-border/50">
                      <td className="py-2 pr-3">{i.label}</td>
                      <td className="py-2 pr-3 tabular-nums">{formatValue(i)}</td>
                      <td className="py-2 pr-3">
                        <PredicateBadge pred={i.predicate} />
                      </td>
                      <td className="py-2 text-muted">{i.note ?? ''}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </Card>
        ))}

      {data && data.extras.length > 0 && (
        <Card title="No predicate">
          <div className="flex flex-wrap gap-6">
            {data.extras.map((x) => (
              <div key={x.key}>
                <div className="text-2xl font-semibold tabular-nums">{x.value}</div>
                <div className="text-muted text-sm">{x.label}</div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {loaded && !data && !error && <EmptyState title="Scorecard could not be loaded" />}

      {canManage && (
        <>
          <Card title="Import scenario log">
            <p className="text-muted text-sm mb-2">
              Paste the scenario-log CSV. Rows are keyed by (scenario, repetition), so re-importing
              updates them in place. Malformed rows are rejected with their line number.
            </p>
            <textarea
              className="w-full h-32 rounded border border-border bg-surface p-2 text-sm font-mono"
              value={csv}
              onChange={(e) => setCsv(e.target.value)}
              placeholder="scenario_id,repetition,executed_at,alerted_at,responded_at,rule_or_feature,technique,detected,note"
            />
            <div className="mt-2 flex items-center gap-3">
              <Button onClick={doImport} disabled={!csv.trim()}>
                Import
              </Button>
              {importMsg && <span className="text-muted text-sm">{importMsg}</span>}
            </div>
          </Card>

          <Card title="Manual input: report preparation time">
            <div className="flex items-end gap-3">
              <div>
                <label className="text-muted text-sm block mb-1">Report preparation time (days)</label>
                <Input
                  type="number"
                  step="0.5"
                  value={prepDays}
                  onChange={(e) => setPrepDays(e.target.value)}
                  placeholder="e.g. 1"
                />
              </div>
              <Button onClick={savePrep} disabled={!prepDays.trim()}>
                Save
              </Button>
              {inputMsg && <span className="text-muted text-sm">{inputMsg}</span>}
            </div>
          </Card>
        </>
      )}
      </div>
    </Page>
  )
}
