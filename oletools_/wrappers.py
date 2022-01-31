from __future__ import annotations

from collections import defaultdict
from typing import Union

from assemblyline.common.str_utils import safe_str
from assemblyline_v4_service.common.result import ResultSection, Heuristic

class ResultSectionWrapper(ResultSection):
    def __init__(self, *args, **kargs) -> None:
        self.reports: list[ReportHeuristic] = []
        super().__init__(*args, auto_collapse=True, **kargs)

    def add_report(self, report: ReportHeuristic) -> None:
        self.reports.append(report)

class ReportHeuristic:
    def __init__(self, heuristic_id: int, context: str, content: Union[bytes, str]) -> None:
        self.id = heuristic_id
        self.context = context
        self.content = content
        self.signatures = []

    def add_signature_id(self, *args):
        self.signatures.append(args)

def get_reports(sections: list[ResultSection]) -> list[ReportHeuristic]:
    reports = []
    for section in sections:
        reports.extend(section.reports if isinstance(section, ResultSectionWrapper) else [])
        reports.extend(get_reports(section.subsections))
    return reports

def build_report(heuristics: list[ReportHeuristic]) -> list[ResultSection]:
    results: list[ResultSection] = []
    id_map: defaultdict[int, list[ReportHeuristic]] = defaultdict(list)
    for heur in heuristics:
        id_map[heur.id].append(heur)

    for id, reports in id_map.items():
        content_map = defaultdict(list)
        heuristic = Heuristic(id)
        for report in reports:
            content_map[safe_str(report.content)].append(report.context)
            for signature in report.signatures:
                heuristic.add_signature_id(*signature)
        body: list[str] = [heuristic.definition.description + '\n']
        for content, contexts in content_map.items():
            contexts = [context for context in contexts if context]
            if content == '':
                body.extend(contexts)
            else:
                body.append(content)
                if len(contexts) == 0:
                    pass
                elif len(contexts) == 1:
                    body.append(f'was found in: {contexts[0]}')
                else:
                    body.append('was found in:')
                    body.extend(['\t' + context for context in contexts])
        results.append(ResultSection(heuristic.definition.name, '\n'.join(body), heuristic=heuristic))

    return sorted(results, key=lambda r: r.heuristic.score, reverse=True) # type: ignore

