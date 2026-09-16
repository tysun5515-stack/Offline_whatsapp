with open('src/webapp/templates/dashboard.html', 'r', encoding='utf-8') as f:
    content = f.read()

import re

# We want to restore the top of dashboard.html up to the Metric Cards
# The beginning should look like this:
replacement = '''{% extends "layout.html" %}
{% block title %}Dashboard — WA Analytics{% endblock %}

{% block dashboard %}
<!-- Welcome Section -->
<div>
  <h2 class="text-2xl font-bold text-gray-900">Welcome, Analyst!</h2>
  <p class="text-gray-500 text-sm mt-1">Analyze and visualize WhatsApp traffic from PCAP files with ease.</p>
</div>

{% if not uploads %}
<!-- -- Smart Empty State -- -->
<div class="bg-white border border-gray-200 rounded-xl p-10 text-center shadow-sm max-w-3xl mx-auto mt-8">
  <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-50 text-blue-500 mb-6">
    <i class="fa-solid fa-satellite-dish text-3xl"></i>
  </div>
  <h3 class="text-xl font-bold text-gray-900 mb-2">Awaiting Evidence</h3>
  <p class="text-gray-500 mb-8 max-w-lg mx-auto">No filtered WhatsApp captures were found for the current scope. To begin analysis, you need to upload PCAP files and run the extraction filter.</p>
  
  <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-left">
    <div class="border border-gray-100 rounded-lg p-5 hover:border-blue-300 hover:shadow-md transition-all group">
      <div class="flex items-start">
        <i class="fa-solid fa-cloud-arrow-up text-blue-500 mt-1 mr-3"></i>
        <div>
          <h4 class="font-semibold text-gray-800 group-hover:text-blue-600 transition-colors">1. Register New Captures</h4>
          <p class="text-xs text-gray-500 mt-1 mb-3">Upload raw PCAP or PCAPNG files directly into the platform.</p>
          <a href="{{ url_for('interface1') }}" class="text-sm font-medium text-blue-600 hover:text-blue-700">Go to Upload Evidence &rarr;</a>
        </div>
      </div>
    </div>
    
    <div class="border border-gray-100 rounded-lg p-5 hover:border-indigo-300 hover:shadow-md transition-all group">
      <div class="flex items-start">
        <i class="fa-solid fa-filter text-indigo-500 mt-1 mr-3"></i>
        <div>
          <h4 class="font-semibold text-gray-800 group-hover:text-indigo-600 transition-colors">2. Run Extraction Filter</h4>
          <p class="text-xs text-gray-500 mt-1 mb-3">If you already uploaded evidence, go to Storage to run the WA filter.</p>
          <a href="{{ url_for('evidence_storage', view='raw') }}" class="text-sm font-medium text-indigo-600 hover:text-indigo-700">Go to Evidence Storage &rarr;</a>
        </div>
      </div>
    </div>
  </div>
</div>

{% else %}

<!-- -- Metric Cards -- -->
<div class="grid grid-cols-1 md:grid-cols-5 gap-4">'''

content = re.sub(r'^{% extends "layout.html" %}.*?<div class="grid grid-cols-1 md:grid-cols-5 gap-4">', replacement, content, flags=re.DOTALL)

with open('src/webapp/templates/dashboard.html', 'w', encoding='utf-8') as f:
    f.write(content)
print("Done")
