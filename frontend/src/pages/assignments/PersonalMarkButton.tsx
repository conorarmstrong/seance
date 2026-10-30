import { useMutation, useQueryClient } from "@tanstack/react-query";
import { addPersonalBookmark } from "./api";

/**
 * Add the artifact to the signed-in examiner's personal bookmarks (§3.15): a
 * private scratch mark, seen only by its author and never printed in a
 * report. Promoting it to the shared bookmarks is a separate, audited step on
 * the Bookmarks page.
 */
export function PersonalMarkButton({
  caseId,
  artifactId,
}: {
  caseId: string;
  artifactId: string;
}) {
  const queryClient = useQueryClient();
  const mark = useMutation({
    mutationFn: () => addPersonalBookmark(caseId, artifactId),
    onSuccess: () =>
      queryClient.invalidateQueries({
        queryKey: ["personal-bookmarks", caseId],
      }),
  });
  return (
    <>
      <button
        type="button"
        className="btn"
        title="A private mark only you see. It is never included in a report unless you add it to the shared bookmarks."
        disabled={mark.isPending || mark.isSuccess}
        onClick={() => mark.mutate()}
      >
        {mark.isSuccess ? "Marked privately" : "Mark privately"}
      </button>
      {mark.error && (
        <span className="error-note" role="alert">
          Not marked: {(mark.error as Error).message}
        </span>
      )}
    </>
  );
}
