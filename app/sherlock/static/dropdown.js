const dropdowns = () => document.querySelectorAll("details.dropdown");

dropdowns().forEach((dropdown) => {
  dropdown.addEventListener("toggle", () => {
    if (!dropdown.open) return;
    dropdowns().forEach((other) => { if (other !== dropdown) other.open = false; });
  });
});

document.addEventListener("click", (event) => {
  dropdowns().forEach((dropdown) => {
    if (dropdown.open && !dropdown.contains(event.target)) dropdown.open = false;
  });
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") dropdowns().forEach((dropdown) => { dropdown.open = false; });
});
