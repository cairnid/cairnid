<script lang="ts">
  export let codes: string[] = [];
</script>

{#if codes.length}
  <div class="recovery-code-panel">
    <strong>Recovery codes</strong>
    <div class="form-grid recovery-code-grid">
      {#each codes as code}
        <input value={code} readonly />
      {/each}
    </div>
  </div>
{/if}
