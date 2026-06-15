<script lang="ts">
  import {
    Activity,
    AppWindow,
    KeyRound,
    ScrollText,
    Shield,
    Users,
    type LucideIcon
  } from '@lucide/svelte';

  type NavLink = {
    href: string;
    label: string;
    icon: LucideIcon;
  };

  const links: NavLink[] = [
    { href: '/admin', label: 'Overview', icon: Activity },
    { href: '/admin/users', label: 'Users', icon: Users },
    { href: '/admin/groups', label: 'Groups', icon: Shield },
    { href: '/admin/applications', label: 'Applications', icon: AppWindow },
    { href: '/admin/audit', label: 'Audit', icon: ScrollText }
  ];
</script>

<div class="app-shell">
  <aside class="sidebar">
    <div class="brand">
      <KeyRound size={22} />
      <span>Cairn Identity</span>
    </div>
    <nav>
      {#each links as link}
        {@const Icon = link.icon}
        <a class="nav-link" href={link.href}>
          <Icon size={18} />
          <span>{link.label}</span>
        </a>
      {/each}
    </nav>
  </aside>
  <main class="content">
    <slot />
  </main>
</div>
