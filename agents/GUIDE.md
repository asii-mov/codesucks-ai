<pre>
This `README.md` is designed to guide Gemini in creating multi-agent system prompts, leveraging a philosophy of natural language-based orchestration and 'soft states' for efficient context management.

***

# README.md: Crafting Multi-Agent System Prompts with Soft States

This guide outlines a powerful approach for defining complex multi-agent systems using natural language, as demonstrated by the "Parallel Research Orchestrator". The core idea is to enable rapid prototyping and value extraction from agentic systems without the overhead of traditional coding or heavy infrastructure.

## 1. Core Philosophy: Natural Language & Soft States

The approach described centres on building multi-agent systems primarily with **natural language**. This method is "amazing for building multi-agent systems with natural language" and "generalized agent systems".

A key innovation is the use of **'soft states'**. These are **natural language-based, semi-structured states** that agents use to communicate and share context.

*   **Mechanism**: Soft states are implemented as a **folder structure with JSON files** that agents can read from and write to. Each agent maintains its own state file to prevent conflicts.
*   **Purpose**: They allow for **very easy context sharing and context management** across various agents and systems. This provides approximately **83% of the value with around 20% of the overhead** compared to full production systems, enabling rapid system setup and value extraction.
*   **Caveats**: 'Soft states' are so named because there is **no guaranteed state integrity** (agents update as they work, but updates are not strictly enforced) and **no real access control** (any agent can potentially view another agent's state, which could lead to unexpected behaviours). However, for many use cases, this is not a significant issue.

## 2. System Architecture: Parent-Subagent Orchestration

This philosophy champions a **parent agent that orchestrates and delegates to various sub-agents**.

*   The parent agent spawns sub-agents for specific tasks.
*   Sub-agents complete their assigned tasks, report back, and update their own state files.
*   The parent agent then aggregates the results, allowing for **multi-agent workflows without any infrastructure code**.
*   The system allows for **non-blocking parallel execution** through this distributed state management, where the orchestrator monitors progress without halting execution.

## 3. Designing a Multi-Agent System: The Prompt Structure for Gemini

To create effective multi-agent system prompts, Gemini should consider the following components for any given topic:

### A. System Overview
*   **`name`**: A concise name for the overall system (e.g., `research-orchestrator`).
*   **`description`**: A brief explanation of the system's purpose, its specialisation, and when it should be used (e.g., "Expert research orchestration specialist. Decomposes complex research requests, coordinates parallel sub-agents, and synthesizes comprehensive findings. Use for deep codebase investigation and multi-faceted technical research.").
*   **Role/Value Proposition**: Emphasise its core value (e.g., "You operate as a **force multiplier** for complex tasks by leveraging parallel processing through sub-agents. Your value lies in transforming broad, ambiguous questions into structured, parallelizable sub-queries that can be investigated simultaneously, dramatically reducing time while increasing comprehensiveness.").

### B. Initialisation/Entry Point
*   Define a clear starting mechanism (e.g., a custom slash command or an API call).
*   Specify initial actions:
    *   Parsing the initial request.
    *   Creating a unique session identifier and a dedicated folder structure for the session (e.g., `[session_name]/sub_agents/`).
    *   Initialising the main agent's state file (e.g., `orchestrator_state.json`) with a specified JSON structure.
    *   Spawning the main agent and notifying the user.

### C. Main Agent Definition (e.g., `Research Orchestrator`)

*   **Role**: Define the primary coordinating agent responsible for understanding the overall query, decomposing it, delegating tasks, and synthesising final results.
*   **Key Capabilities/Expertise**: List specific skills or knowledge areas crucial for its role (e.g., "Deep understanding of effective decomposition strategies," "Mastery in orchestrating parallel agent workflows," "Skill in synthesizing diverse findings").
*   **Tools**: List the tools the main agent has access to (e.g., `Read`, `Edit`, `Bash`, `Glob`, `Grep`, `LS`, `Task`, `Write`).
*   **State File Structure (JSON)**: Provide a detailed JSON schema for its state file. This file will be continuously updated by the agent.
    *   **Example Fields (adapt for specific topic)**: `session_id`, `created_at`, `current_phase` (e.g., `INITIALIZATION`, `REQUEST_ANALYSIS`, `QUERY_DECOMPOSITION`, `PARALLEL_EXECUTION`, `SYNTHESIS`, `COMPLETED`), `original_request`, `request_analysis` (with `summarized_intent`, `identified_needs`, `key_concepts`), `initial_understanding` (with `overview`, `key_components`, `relevant_areas`), `decomposed_queries` (list of sub-query objects), `sub_agents` (list of spawned sub-agent details), `synthesis_results` (with `key_insights`, `total_items_examined`, `recommendations`), `final_report_path`, `completed_at`.
*   **Detailed Workflow Instructions**: Provide clear, sequential steps for the agent's operation, explicitly stating when and how it should update its state file.
    1.  **Load State**: Read its own state file upon activation.
    2.  **Request Analysis**: Parse the initial request, identify explicit/implicit needs, scope boundaries, and extract key concepts. **Update relevant fields in state** (e.g., `request_analysis`, `summarized_intent`).
    3.  **Initial Understanding**: Perform a high-level scan of the relevant data/codebase/information to build a mental model. **Update state** (e.g., `initial_understanding`).
    4.  **Query Decomposition**: Break down the original query into independent, focused sub-queries suitable for parallel execution. For each sub-query, define a specific objective, likely locations to investigate, search terms, and an expected output format. **Update state** (e.g., `decomposed_queries` and `sub_agents` assignments).
    5.  **Parallel Execution**: For each sub-query, create an initial state file for the sub-agent. **Spawn ALL sub-agents in parallel** using a single `Task` tool invocation. Provide each sub-agent with its specific query details, state file path, and session directory. **Update orchestrator state** with spawn details.
    6.  **Monitor Progress**: Periodically check sub-agent state files without blocking execution. Track completion percentages.
    7.  **Synthesis**: Once all sub-agents report completion, read all their completed state files. Analyse findings to identify common patterns, complementary insights, and key examples. Structure the synthesis by grouping and prioritising findings. **Update state** (e.g., `synthesis_results`).
    8.  **Report Generation**: Compile the synthesised findings into a comprehensive report in a structured format (e.g., Markdown). Save the report to the session directory.
    9.  **Finalise State**: Mark the current phase as "COMPLETED" and update final report path and completion timestamp in its state.
    *   **Auditing**: Ensure the agent tracks all examined data/file paths with relevance scores and documents the reasoning behind each sub-query, preserving the complete chain of investigation.

### D. Sub-Agent Definition (can be multiple types)
*   **Role**: Define the specific, focused tasks for the sub-agents, usually derived from the decomposed queries (e.g., "conduct focused research on a specific subquery").
*   **State File Structure (JSON)**: Provide a detailed JSON schema for its own state file (e.g., `subagent_state_[ID].json`).
    *   **Example Fields (adapt for specific topic)**: `assigned_query`, `search_history` (log of actions taken), `data_analysed` (list of specific items reviewed), `findings` (detailed notes), `summary_for_main_agent` (concise summary of findings).
*   **Detailed Workflow Instructions**: Provide clear, sequential steps for the sub-agent's operation.
    1.  **Initialise State**: Create its own state file and populate it with the `assigned_query`.
    2.  **Execute Task**: Perform its specific research/analysis/coding task, reading relevant files/data, taking notes, and identifying useful information based on its assigned sub-query.
    3.  **Compile Result**: Consolidate its findings into a `summary_for_main_agent`.
    4.  **Update State**: Continuously update its state file (`search_history`, `data_analysed`, `findings`, `summary_for_main_agent`) as it works.
    5.  **Report Back**: Signal completion to the main orchestrator, ensuring its state file is accessible for synthesis.

## 4. Key Design Principles for Effective Systems

When designing new multi-agent systems, ensure these principles are applied:

*   **Maximise Parallelisation**: Identify all possible parallel paths and decompose queries into truly independent sub-tasks that can run simultaneously.
*   **Non-Blocking Execution**: Design agents and workflows such that the orchestrator monitors progress without waiting for individual agents; instead, it monitors collectively.
*   **Distributed State Management**: Each agent maintains its own state file, and state updates are atomic and immediately persisted.
*   **Completeness**: Ensure all aspects of the original request are covered without gaps.
*   **Traceability**: All findings must reference specific data points, files, or code.
*   **Actionable Output**: Provide clear implementation guidance and next steps in the final report.
*   **Agent Autonomy**: Allow sub-agents to spawn their own sub-agents for deeper investigation if needed.
*   **Explicit Instructions**: Provide agents with **very detailed instructions on their workflow** and how their state should work, including the JSON structure for their internal state files.

***

**Gemini's Task:**

Using the above principles and structure, **create several distinct multi-agent system definitions for different topics** you deem suitable (e.g., a "Content Creator Orchestrator," a "Software Bug Fixer," a "Market Research Analyst," etc.). Each definition should rigorously follow the format:

*   **System Overview**
*   **Initialisation/Entry Point**
*   **Main Agent Definition (Role, Capabilities, Tools, State File Structure, Detailed Workflow)**
*   **One or more Sub-Agent Definitions (Role, State File Structure, Detailed Workflow)**
*   An explicit section explaining **how 'soft states' are used for context sharing** within that specific system.

Ensure the "Detailed Workflow Instructions" are comprehensive enough for an LLM to conceptually execute the defined steps for each agent.
</pre>