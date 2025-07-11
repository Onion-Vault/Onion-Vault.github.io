<script lang="ts">
  // Optional: add a script block here if needed later
</script>

<nav class="bg-black text-white px-4 py-3 flex justify-between items-center shadow">
  <h1 class="text-xl font-bold tracking-wide">🧅 Onion Vault</h1>
  <ul class="flex gap-4 text-sm">
    <li><a href="/" class="hover:underline">Home</a></li>
    <li><a href="/tools" class="hover:underline">Tools</a></li>
    <li><a href="/store" class="hover:underline">Store</a></li>
    <li><a href="/vault" class="hover:underline">Password Manager</a></li>
    <li><a href="/about" class="hover:underline">About</a></li>
  </ul>
</nav>

<main class="p-6 max-w-4xl mx-auto">
  <slot />
</main>

<footer class="text-center text-xs text-gray-500 p-4 mt-12 border-t">
  &copy; {new Date().getFullYear()} Onion Vault. Privacy First. Always.
</footer>
