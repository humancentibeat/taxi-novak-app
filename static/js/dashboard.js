let scrollPosition = 0;
document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('createEntryModal');
    const deleteButton = document.getElementById('deleteButton');
    // Ensure modal is hidden by default
    modal.classList.add('hidden');
    // Handle type changes
    document.getElementById('type').addEventListener('change', function() {
        const timeFields = document.getElementById('timeFields');
        if (this.value === 'Arbeit') {
            timeFields.classList.remove('hidden');
            // Set default times
            document.getElementById('time_from').value = this.dataset["time-from"] || '08:00';
            document.getElementById('time_to').value = this.dataset["time-to"] || '16:00';
        } else {
            timeFields.classList.add('hidden');
        }
    });

    // Open modal and populate data
    document.querySelectorAll('td[data-user-id]').forEach(cell => {
        cell.addEventListener('click', function() {
            const userId = this.dataset.userId;
            const date = this.dataset.date;
            const entryId = this.dataset.entryId;
            const entryType = this.dataset.type;
            const driverName = this.closest('tr').querySelector('td:first-child').textContent;
            
            // Store current scroll position
            sessionStorage.setItem('scrollPosition', window.scrollY);

            // Set modal values
            document.getElementById('modalDriverName').textContent = driverName;
            document.getElementById('modalDate').textContent = date;
            document.getElementById('modalUserId').value = userId;
            document.getElementById('modalEntryId').value = entryId || '';
            document.getElementById('date_from').value = date;
            document.getElementById('date_to').value = date;

            // Handle existing entry data
            const form = document.getElementById('entryForm');
            if (entryId) {
                form.action = `/entries/edit/${entryId}`;
                document.getElementById('submitText').textContent = 'Aktualisieren';
                document.getElementById('modalAction').textContent = 'Bearbeiten';
                deleteButton.classList.remove('hidden');

                // Populate existing data
                document.getElementById('type').value = entryType;
                if (entryType === 'Arbeit') {
                    document.getElementById('time_from').value = this.dataset["time-from"] || '08:00';
                    document.getElementById('time_to').value = this.dataset["time-to"] || '16:00';
                    document.getElementById('timeFields').classList.remove('hidden');
                }
            } else {
                form.action = '/entries/create';
                document.getElementById('submitText').textContent = 'Erstellen';
                document.getElementById('modalAction').textContent = 'Neue';
                deleteButton.classList.add('hidden');
            }

            // Trigger type change to show/hide time fields
            document.getElementById('type').dispatchEvent(new Event('change'));

            // Show modal
            modal.classList.remove('hidden');
        });
    });

    // Close modal handler
    document.getElementById('closeModalButton').addEventListener('click', function() {
        modal.classList.add('hidden');
        // Restore scroll position properly
        const savedPosition = sessionStorage.getItem('scrollPosition');
        if (savedPosition !== null) {
            window.scrollTo({ top: parseInt(savedPosition, 10), behavior: 'instant' });
        }
    });

    // Delete button handler
    deleteButton.addEventListener('click', function() {
        const warningNotification = document.getElementById('warningNotification');
        const confirmDelete = document.getElementById('confirmDelete');
        const cancelDelete = document.getElementById('cancelDelete');

        // Show warning notification
        warningNotification.classList.remove('hidden');

        // Confirm deletion (only fires once)
        confirmDelete.addEventListener('click', function handleConfirmDelete() {
            const entryId = document.getElementById('modalEntryId').value;
            if (entryId) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = `/entries/delete/${entryId}`;
                const weekInput = document.createElement('input');  

                weekInput.type = 'hidden';  
                weekInput.name = 'week';  
                weekInput.value = new URLSearchParams(window.location.search).get('week') || '0';

                const csrfInput = document.createElement('input');
                csrfInput.type = 'hidden';
                csrfInput.name = 'csrf_token';
                csrfInput.value = document.querySelector('input[name="csrf_token"]').value;
                form.appendChild(weekInput);
                form.appendChild(csrfInput);
                document.body.appendChild(form);
                form.submit();
            }
            warningNotification.classList.add('hidden');

            // Remove event listener after execution
            confirmDelete.removeEventListener('click', handleConfirmDelete);
        }, { once: true });

        // Cancel deletion (only fires once)
        cancelDelete.addEventListener('click', function handleCancelDelete() {
            warningNotification.classList.add('hidden');
            cancelDelete.removeEventListener('click', handleCancelDelete);
        }, { once: true });
    });

});

// Open modal when "Copy Week button" is clicked beta
document.getElementById('openCopyModal').addEventListener('click', function() {
    document.getElementById('copyWeekModal').style.display = 'block';
  });
  
  // Close modal when X is clicked
  document.querySelector('.close').addEventListener('click', function() {
    document.getElementById('copyWeekModal').style.display = 'none';
  });
  
  // Handle form submission
document.getElementById('copyForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    // Get the week parameter from the URL
    const urlParams = new URLSearchParams(window.location.search);
    const week = urlParams.get('week') || 0; 

    // Create FormData and append the week parameter
    const formData = new FormData(this);
    formData.append('week', week); // Add the week parameter to the form data
    
    fetch('/copy-week-entries', {
      method: 'POST',
      body: formData
    }).then(response => {
      if (response.ok) {
        window.location.reload(); // Refresh to show changes
      } else {
        alert('Copy failed. Please try again.');
      }
    });
 
  });


// Handle "Clear Week" button click
document.getElementById('clearWeekButton').addEventListener('click', function() {
    const warningNotification = document.getElementById('warningNotification');
    const confirmDelete = document.getElementById('confirmDelete');
    const cancelDelete = document.getElementById('cancelDelete');

    // Show warning notification
    warningNotification.classList.remove('hidden');

    // Confirm clear week (only fires once)
    confirmDelete.addEventListener('click', function handleConfirmClear() {
        // Get the week parameter from the URL
        const week = new URLSearchParams(window.location.search).get('week') || '0';

        // Create a form to submit the request
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/clear-week-entries'; // Match the backend route

        // Add week as a hidden input
        const weekInput = document.createElement('input');
        weekInput.type = 'hidden';
        weekInput.name = 'week';
        weekInput.value = week;
        form.appendChild(weekInput);

        // Add CSRF token as a hidden input
        const csrfInput = document.createElement('input');
        csrfInput.type = 'hidden';
        csrfInput.name = 'csrf_token';
        csrfInput.value = document.querySelector('input[name="csrf_token"]').value;
        form.appendChild(csrfInput);

        // Append the form to the body and submit it
        document.body.appendChild(form);
        form.submit();

        // Hide the warning notification
        warningNotification.classList.add('hidden');

        // Remove event listener after execution
        confirmDelete.removeEventListener('click', handleConfirmClear);
    }, { once: true });

    // Cancel clear week (only fires once)
    cancelDelete.addEventListener('click', function handleCancelClear() {
        warningNotification.classList.add('hidden');
        cancelDelete.removeEventListener('click', handleCancelClear);
    }, { once: true });
});