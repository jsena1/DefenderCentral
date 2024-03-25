function gotoAbout(){
    window.location.href = '/templates/about.html';
}
function gotoHome(){
    window.location.href = '/templates/main.html';
}

function scanURL() {
    var url = document.getElementById('urlInput').value;
    
    $.ajax({
        type: 'POST',
        url: '/scan_url',
        data: { url: url },
        success: function (data) {
            $('#analysisReport').text('loading...please wait');
            $('#scanResults').text(JSON.stringify(data.results, null, 2));
            $('#analysisReportContainer').hide();
            $('#communityCommentsContainer').hide();
            $('#zenrowsAnalysisContainer').hide();
            $('#resultContainer').show();

            if (data.results && data.results.data && data.results.data.id) {
                var analysisId = data.results.data.id.split('-')[1];

                // Fetch analysis report after scanning
                $.ajax({
                    type: 'GET',
                    url: '/get_analysis_report',
                    data: { analysisId: analysisId },
                    success: function (analysisReport) {

                        var lastAnalysisStats = analysisReport.data.attributes.last_analysis_stats;
                        //$('#analysisReport').text(JSON.stringify({ last_analysis_stats: lastAnalysisStats }, null, 2));
                        //$('#analysisReportContainer').show();
                         // Check a specific variable in the JSON data
                        if (lastAnalysisStats.malicious !== '0') {
                            // Modify the output based on the condition
                            $('#analysisReport').text('Sumbbited url scanned to be mailcious! be cautioys outhere');
                        } else if(lastAnalysisStats.suspicious !== '0'){
                            $('#analysisReport').text('Sumbbited url scanned to be suspicous! verify if you got the url froma reilable source');
                         }else{
                            $('#analysisReport').text('is clean! but becaredul out there');
                         }
                         $('#analysisReportContainer').show();
                    },
                    error: function (error) {
                        console.error('Error fetching analysis report:', error);
                        alert('Failed to fetch analysis report. Please try again.');
                    }
                });
            } else {
                console.error('Invalid data received:', data);
                alert('Failed to retrieve analysis ID from the response. Please try again.');
            }
        },
        error: function (error) {
            console.error('Error scanning URL:', error);
            alert('Failed to scan URL. Please try again.');
        }
    });
}
