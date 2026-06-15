<script lang="ts">
  import { ShieldCheck } from '@lucide/svelte';
  import type { ConsentGrantMode, ConsentPolicyTemplate } from '$lib/api';
  import { grantModeLabel } from './helpers';

  export let templates: ConsentPolicyTemplate[] = [];
  export let policySlug = '';
  export let policyName = '';
  export let policyGrantMode: ConsentGrantMode = 'required_once';
  export let onCreate: () => void | Promise<void>;
</script>

<section class="panel panel-spaced">
  <div class="toolbar">
    <strong>Consent policy templates</strong>
  </div>
  <div class="form-grid">
    <div class="field">
      <label for="policy-slug">Slug</label>
      <input id="policy-slug" bind:value={policySlug} />
    </div>
    <div class="field">
      <label for="policy-name">Policy name</label>
      <input id="policy-name" bind:value={policyName} />
    </div>
    <div class="field">
      <label for="policy-grant-mode">Grant mode</label>
      <select id="policy-grant-mode" bind:value={policyGrantMode}>
        <option value="required_once">Required once</option>
        <option value="always_required">Always required</option>
      </select>
    </div>
  </div>
  <button class="secondary-button section-action" onclick={onCreate}>
    <ShieldCheck size={17} />
    <span>Create policy</span>
  </button>
  {#if templates.length}
    <table class="data-table section-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Slug</th>
          <th>Grant mode</th>
        </tr>
      </thead>
      <tbody>
        {#each templates as template}
          <tr>
            <td>{template.name}</td>
            <td>{template.slug}</td>
            <td>{grantModeLabel(template.grant_mode)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</section>
