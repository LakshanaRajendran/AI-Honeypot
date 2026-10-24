import React, { useEffect, useState } from "react";
import { DocumentationPayload } from "../types";

export const TechnicalDocsTab: React.FC = () => {
  const [doc, setDoc] = useState<DocumentationPayload | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [activeHeading, setActiveHeading] = useState<string>("");

  useEffect(() => {
    fetch("/api/documentation")
      .then((res) => res.json())
      .then((data) => {
        setDoc(data);
        if (data.headings && data.headings.length > 0) {
          setActiveHeading(data.headings[0]);
        }
        setLoading(false);
      })
      .catch((err) => {
        console.error("Failed to load documentation:", err);
        setLoading(false);
      });
  }, []);

  const filteredHeadings = doc?.headings?.filter((h) =>
    h.toLowerCase().includes(searchTerm.toLowerCase())
  ) || [];

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <svg className="w-6 h-6 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
            </svg>
            System Technical Guide &amp; Architecture Specification
          </h2>
          <p className="text-xs text-slate-300 mt-1">
            Comprehensive reference manual covering all 26 technical dimensions, codebase structure, formulas, and security boundaries.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <a
            href="/api/documentation"
            download="PROJECT_TECHNICAL_GUIDE.md"
            className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-2 border border-slate-700 transition-colors"
          >
            <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Download Markdown
          </a>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Table of Contents Sidebar */}
        <div className="lg:col-span-1 bg-slate-900/80 border border-slate-800 rounded-xl p-4 h-fit max-h-[750px] flex flex-col">
          <div className="mb-3">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">
              Table of Contents
            </span>
            <input
              type="text"
              placeholder="Search sections..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:ring-1 focus:ring-cyan-500 outline-none"
            />
          </div>

          <div className="overflow-y-auto space-y-1 pr-1 flex-1">
            {filteredHeadings.map((heading) => (
              <a
                key={heading}
                href={`#section-${heading.replace(/[^a-zA-Z0-9]/g, "-").toLowerCase()}`}
                onClick={() => setActiveHeading(heading)}
                className={`block text-xs py-1.5 px-2.5 rounded transition-colors truncate ${
                  activeHeading === heading
                    ? "bg-cyan-950/70 text-cyan-300 font-semibold border-l-2 border-cyan-400"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                }`}
                title={heading}
              >
                {heading}
              </a>
            ))}
          </div>
        </div>

        {/* Documentation Content Area */}
        <div className="lg:col-span-3 bg-slate-900/80 border border-slate-800 rounded-xl p-6 lg:p-8 max-h-[750px] overflow-y-auto">
          {loading ? (
            <div className="text-center py-12 text-slate-400">Loading documentation...</div>
          ) : doc ? (
            <div className="prose prose-invert prose-cyan max-w-none text-slate-300 text-xs leading-relaxed space-y-6">
              {doc.content_markdown.split(/\n(?=## )/).map((sec, idx) => {
                const lines = sec.trim().split("\n");
                const headingLine = lines[0] || "";
                const headingText = headingLine.replace(/^##\s+/, "");
                const body = lines.slice(1).join("\n");
                const sectionId = `section-${headingText.replace(/[^a-zA-Z0-9]/g, "-").toLowerCase()}`;

                return (
                  <div key={idx} id={sectionId} className="pt-4 border-t border-slate-800/60 first:border-0 first:pt-0">
                    {headingLine.startsWith("## ") ? (
                      <h2 className="text-lg font-bold text-white mb-3 text-cyan-300 flex items-center gap-2">
                        <span className="w-2 h-2 rounded bg-cyan-400"></span>
                        {headingText}
                      </h2>
                    ) : (
                      <h1 className="text-xl font-extrabold text-white mb-4">{headingLine.replace(/^#\s+/, "")}</h1>
                    )}
                    <div className="whitespace-pre-wrap font-sans text-xs text-slate-300 leading-relaxed">
                      {body}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-center py-12 text-red-400">Failed to render documentation.</div>
          )}
        </div>
      </div>
    </div>
  );
};
