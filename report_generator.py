# report_generator.py
# Creates complete PDF forensic report for all 3 attacks

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime
import os


def create_pdf_report(forensic_data):
    """
    Creates complete PDF forensic report

    Includes all 3 attack types:
    - Brute Force
    - Unauthorized Access
    - Ransomware
    """

    os.makedirs("reports", exist_ok=True)

    filename = (
        f"reports/Forensic_Report_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )

    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=20,
        textColor=colors.darkred,
        spaceAfter=6
    )

    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=colors.darkblue,
        spaceBefore=12,
        spaceAfter=6
    )

    subheading_style = ParagraphStyle(
        'CustomSubheading',
        parent=styles['Heading3'],
        fontSize=11,
        textColor=colors.darkred,
        spaceBefore=8,
        spaceAfter=4
    )

    normal_style = styles['Normal']
    normal_style.fontSize = 9

    story = []

    # ─────────────────────────────────────────
    # HEADER
    # ─────────────────────────────────────────

    story.append(Paragraph(
        "CLOUD SECURITY FORENSIC INCIDENT REPORT",
        title_style
    ))

    story.append(HRFlowable(
        width="100%",
        thickness=2,
        color=colors.darkred
    ))
    story.append(Spacer(1, 8))

    # Case Info Table
    case_id = forensic_data.get("case_id", "N/A")
    inv_time = forensic_data.get("investigation_time", "N/A")
    attacks = forensic_data.get("attacks_detected", [])

    severity = "CRITICAL" if len(attacks) >= 2 else (
        "HIGH" if len(attacks) == 1 else "LOW"
    )
    severity_color = (
        colors.red if severity == "CRITICAL"
        else colors.orange if severity == "HIGH"
        else colors.green
    )

    case_data = [
        ["Case ID", case_id,
         "Severity", severity],
        ["Date / Time", inv_time,
         "Attacks Detected", str(len(attacks))],
        ["Attack Types",
         ", ".join(attacks) if attacks else "None",
         "Status", "INVESTIGATION COMPLETE"]
    ]

    case_table = Table(
        case_data,
        colWidths=[100, 180, 100, 160]
    )
    case_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('BACKGROUND', (2, 0), (2, -1), colors.lightgrey),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('TEXTCOLOR', (3, 0), (3, 0), severity_color),
        ('FONTNAME', (3, 0), (3, 0), 'Helvetica-Bold'),
    ]))

    story.append(case_table)
    story.append(Spacer(1, 12))

    # ─────────────────────────────────────────
    # EXECUTIVE SUMMARY
    # ─────────────────────────────────────────

    story.append(Paragraph("1. EXECUTIVE SUMMARY", heading_style))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.darkblue))
    story.append(Spacer(1, 6))

    total_events = forensic_data.get("total_file_events", 0)
    total_alerts = forensic_data.get("total_alerts", 0)
    total_security = forensic_data.get("total_security_events", 0)
    total_blocked = forensic_data.get("total_blocked_entities", 0)

    summary_text = (
        f"This forensic report documents a cloud security incident "
        f"detected on {inv_time}. "
        f"The investigation identified <b>{len(attacks)} attack type(s)</b>: "
        f"<b>{', '.join(attacks) if attacks else 'None detected'}</b>. "
        f"<br/><br/>"
        f"A total of <b>{total_events}</b> file activity events were recorded, "
        f"<b>{total_security}</b> authentication and access security events, "
        f"and <b>{total_alerts}</b> system alerts were generated. "
        f"<b>{total_blocked}</b> IP address(es) or user account(s) "
        f"were blocked by the automated response system."
    )

    story.append(Paragraph(summary_text, normal_style))
    story.append(Spacer(1, 12))

    # ─────────────────────────────────────────
    # ATTACK 1: BRUTE FORCE
    # ─────────────────────────────────────────

    story.append(Paragraph(
        "2. ATTACK 1: BRUTE FORCE PASSWORD ATTACK",
        heading_style
    ))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.darkblue))
    story.append(Spacer(1, 6))

    brute_data = forensic_data.get("brute_force")

    if brute_data:
        # Summary
        bf_summary_data = [
            ["Attacker IP(s)",
             ", ".join(brute_data.get("attacker_ips", ["N/A"]))],
            ["Target Username(s)",
             ", ".join(brute_data.get("usernames_targeted", ["N/A"]))],
            ["Total Failed Attempts",
             str(brute_data.get("total_attempts", 0))],
            ["First Attempt Time",
             brute_data.get("first_attempt", "N/A")],
            ["Last Attempt Time",
             brute_data.get("last_attempt", "N/A")],
            ["Status", "🚨 ATTACK DETECTED & BLOCKED"]
        ]

        bf_table = Table(
            bf_summary_data,
            colWidths=[180, 360]
        )
        bf_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightyellow),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('TEXTCOLOR', (1, 5), (1, 5), colors.red),
            ('FONTNAME', (1, 5), (1, 5), 'Helvetica-Bold'),
        ]))

        story.append(bf_table)
        story.append(Spacer(1, 8))

        # IP Attempt counts
        ip_attempts = brute_data.get("ip_attempts", {})
        if ip_attempts:
            story.append(Paragraph(
                "Failed Login Attempts Per IP:",
                subheading_style
            ))

            attempt_data = [["IP Address", "Failed Attempts", "Risk Level"]]
            for ip, count in ip_attempts.items():
                risk = (
                    "CRITICAL" if count >= 8
                    else "HIGH" if count >= 5
                    else "MEDIUM"
                )
                attempt_data.append([ip, str(count), risk])

            attempt_table = Table(
                attempt_data,
                colWidths=[200, 150, 190]
            )
            attempt_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('TEXTCOLOR', (2, 1), (2, -1), colors.red),
            ]))
            story.append(attempt_table)

    else:
        story.append(Paragraph(
            "✅ No brute force attack detected during this incident.",
            normal_style
        ))

    story.append(Spacer(1, 12))

    # ─────────────────────────────────────────
    # ATTACK 2: RANSOMWARE
    # ─────────────────────────────────────────

    story.append(Paragraph(
        "3. ATTACK 2: RANSOMWARE FILE ENCRYPTION ATTACK",
        heading_style
    ))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.darkblue))
    story.append(Spacer(1, 6))

    ransomware_data = forensic_data.get("ransomware")

    if ransomware_data:
        rs_summary_data = [
            ["Suspicious Files Detected",
             str(ransomware_data.get("suspicious_files_count", 0))],
            ["Files Encrypted/Locked",
             str(ransomware_data.get("locked_files_count", 0))],
            ["Files Deleted by Ransomware",
             str(ransomware_data.get("deleted_files_count", 0))],
            ["Files Restored by System",
             str(ransomware_data.get("restored_files_count", 0))],
            ["Emergency Stops Triggered",
             str(ransomware_data.get("emergency_stops", 0))],
            ["First Ransomware Event",
             ransomware_data.get("first_event", "N/A")],
            ["Last Ransomware Event",
             ransomware_data.get("last_event", "N/A")],
            ["Status", "🚨 ATTACK DETECTED & FILES RESTORED"]
        ]

        rs_table = Table(
            rs_summary_data,
            colWidths=[180, 360]
        )
        rs_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightyellow),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('TEXTCOLOR', (1, 7), (1, 7), colors.red),
            ('FONTNAME', (1, 7), (1, 7), 'Helvetica-Bold'),
        ]))
        story.append(rs_table)
        story.append(Spacer(1, 8))

        # Locked files list
        locked_files = ransomware_data.get("locked_files", [])
        if locked_files:
            story.append(Paragraph(
                "Encrypted/Locked Files Detected:",
                subheading_style
            ))

            locked_data = [["#", "File Name", "Status"]]
            for i, fname in enumerate(locked_files[:15], 1):
                locked_data.append([
                    str(i),
                    fname,
                    "ENCRYPTED → DELETED BY SECURITY"
                ])

            locked_table = Table(
                locked_data,
                colWidths=[30, 280, 230]
            )
            locked_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING', (0, 0), (-1, -1), 4),
                ('TEXTCOLOR', (2, 1), (2, -1), colors.green),
            ]))
            story.append(locked_table)

    else:
        story.append(Paragraph(
            "✅ No ransomware activity detected during this incident.",
            normal_style
        ))

    story.append(Spacer(1, 12))

    # ─────────────────────────────────────────
    # ATTACK 3: UNAUTHORIZED ACCESS
    # ─────────────────────────────────────────

    story.append(Paragraph(
        "4. ATTACK 3: UNAUTHORIZED ACCESS ATTEMPT",
        heading_style
    ))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.darkblue))
    story.append(Spacer(1, 6))

    unauth_data = forensic_data.get("unauthorized_access")

    if unauth_data:
        ua_summary_data = [
            ["Attacker IP(s)",
             ", ".join(unauth_data.get("attacker_ips", ["N/A"]))],
            ["Total Unauthorized Attempts",
             str(unauth_data.get("total_attempts", 0))],
            ["Resources Targeted",
             ", ".join(unauth_data.get("targets_accessed", ["N/A"]))],
            ["First Attempt",
             unauth_data.get("first_attempt", "N/A")],
            ["Last Attempt",
             unauth_data.get("last_attempt", "N/A")],
            ["Status", "🚨 ATTACK DETECTED & IP BLOCKED"]
        ]

        ua_table = Table(
            ua_summary_data,
            colWidths=[180, 360]
        )
        ua_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightyellow),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('TEXTCOLOR', (1, 5), (1, 5), colors.red),
            ('FONTNAME', (1, 5), (1, 5), 'Helvetica-Bold'),
        ]))
        story.append(ua_table)
        story.append(Spacer(1, 8))

        # Attempts per IP
        ip_attempts = unauth_data.get("ip_attempts", {})
        if ip_attempts:
            story.append(Paragraph(
                "Unauthorized Attempts Per IP:",
                subheading_style
            ))

            ua_attempt_data = [
                ["IP Address", "Attempts", "Risk Level"]
            ]
            for ip, count in ip_attempts.items():
                risk = (
                    "CRITICAL" if count >= 5
                    else "HIGH" if count >= 3
                    else "MEDIUM"
                )
                ua_attempt_data.append([ip, str(count), risk])

            ua_attempt_table = Table(
                ua_attempt_data,
                colWidths=[200, 150, 190]
            )
            ua_attempt_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('TEXTCOLOR', (2, 1), (2, -1), colors.red),
            ]))
            story.append(ua_attempt_table)

    else:
        story.append(Paragraph(
            "✅ No unauthorized access detected during this incident.",
            normal_style
        ))

    story.append(Spacer(1, 12))

    # ─────────────────────────────────────────
    # BLOCKED IPs AND USERS
    # ─────────────────────────────────────────

    story.append(Paragraph(
        "5. BLOCKED IPs AND USERS",
        heading_style
    ))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.darkblue))
    story.append(Spacer(1, 6))

    blocked_entities = forensic_data.get("blocked_entities", [])

    if blocked_entities:
        blocked_table_data = [
            ["Time Blocked", "Type", "IP/Username",
             "Reason", "Status"]
        ]
        for entity in blocked_entities:
            blocked_table_data.append([
                entity[1],
                entity[2],
                entity[3],
                entity[4][:45] + "..." if len(entity[4]) > 45
                else entity[4],
                entity[5]
            ])

        blocked_table = Table(
            blocked_table_data,
            colWidths=[100, 50, 100, 210, 80]
        )
        blocked_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.black),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('TEXTCOLOR', (4, 1), (4, -1), colors.red),
            ('FONTNAME', (4, 1), (4, -1), 'Helvetica-Bold'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.white, colors.lightgrey])
        ]))
        story.append(blocked_table)
    else:
        story.append(Paragraph(
            "No entities were blocked during this incident.",
            normal_style
        ))

    story.append(Spacer(1, 12))

    # ─────────────────────────────────────────
    # FULL ATTACK TIMELINE
    # ─────────────────────────────────────────

    story.append(Paragraph(
        "6. COMPLETE ATTACK TIMELINE",
        heading_style
    ))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.darkblue))
    story.append(Spacer(1, 6))

    timeline = forensic_data.get("timeline", [])

    if timeline:
        tl_data = [["Time", "Category", "Event",
                    "Actor/IP", "Target"]]

        for event in timeline[:30]:
            tl_data.append([
                event.get("time", "")[:19],
                event.get("category", ""),
                event.get("event", "")[:20],
                event.get("ip", "")[:15],
                event.get("target", "")[:20]
            ])

        tl_table = Table(
            tl_data,
            colWidths=[95, 95, 110, 95, 105]
        )
        tl_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 4),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.white, colors.lightblue])
        ]))
        story.append(tl_table)

        if len(timeline) > 30:
            story.append(Spacer(1, 4))
            story.append(Paragraph(
                f"(Showing first 30 of {len(timeline)} events. "
                f"Full logs saved in database.)",
                normal_style
            ))
    else:
        story.append(Paragraph(
            "No timeline events recorded.",
            normal_style
        ))

    story.append(Spacer(1, 12))

    # ─────────────────────────────────────────
    # RESPONSE ACTIONS TAKEN
    # ─────────────────────────────────────────

    story.append(Paragraph(
        "7. AUTOMATED RESPONSE ACTIONS TAKEN",
        heading_style
    ))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.darkblue))
    story.append(Spacer(1, 6))

    response_actions = []

    if brute_data:
        response_actions.append(
            "✅ Brute force attack detected and blocked"
        )
        response_actions.append(
            f"✅ Attacker IP(s) {brute_data.get('attacker_ips', [])} blocked"
        )
        response_actions.append(
            f"✅ Target username(s) {brute_data.get('usernames_targeted', [])} protected"
        )

    if ransomware_data:
        response_actions.append(
            "✅ Ransomware activity detected via file extension monitoring"
        )
        response_actions.append(
            f"✅ {ransomware_data.get('locked_files_count', 0)} encrypted files removed from cloud"
        )
        response_actions.append(
            f"✅ {ransomware_data.get('restored_files_count', 0)} original files restored from backup"
        )
        response_actions.append(
            "✅ Emergency stop triggered to halt further encryption"
        )

    if unauth_data:
        response_actions.append(
            "✅ Unauthorized access attempts detected and logged"
        )
        response_actions.append(
            f"✅ Attacker IP(s) {unauth_data.get('attacker_ips', [])} blocked"
        )
        response_actions.append(
            "✅ All target resources protected from unauthorized access"
        )

    response_actions.append(
        "✅ All evidence saved to forensic-evidence bucket in MinIO"
    )
    response_actions.append(
        "✅ Complete forensic PDF report generated"
    )

    for action in response_actions:
        story.append(Paragraph(action, normal_style))
        story.append(Spacer(1, 3))

    story.append(Spacer(1, 12))

    # ─────────────────────────────────────────
    # SECURITY EVENTS LOG
    # ─────────────────────────────────────────

    story.append(Paragraph(
        "8. SECURITY EVENTS LOG",
        heading_style
    ))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.darkblue))
    story.append(Spacer(1, 6))

    security_events = forensic_data.get("security_events", [])

    if security_events:
        se_data = [["Time", "Event Type", "Username",
                    "IP Address", "Target", "Status"]]

        for event in security_events[:25]:
            se_data.append([
                event[1][:19],
                event[2][:18],
                event[3][:12],
                event[4][:15],
                event[6][:20],
                event[7][:10]
            ])

        se_table = Table(
            se_data,
            colWidths=[90, 110, 75, 90, 105, 70]
        )
        se_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 4),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.white, colors.lightgrey])
        ]))
        story.append(se_table)

        if len(security_events) > 25:
            story.append(Spacer(1, 4))
            story.append(Paragraph(
                f"(Showing first 25 of {len(security_events)} events)",
                normal_style
            ))
    else:
        story.append(Paragraph(
            "No security events recorded.",
            normal_style
        ))

    story.append(Spacer(1, 12))

    # ─────────────────────────────────────────
    # RECOMMENDATIONS
    # ─────────────────────────────────────────

    story.append(Paragraph(
        "9. SECURITY RECOMMENDATIONS",
        heading_style
    ))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.darkblue))
    story.append(Spacer(1, 6))

    recommendations = [
        ("Immediate Actions", [
            "Change all MinIO access keys and secret keys immediately",
            "Reset all user account passwords",
            "Review and revoke any suspicious access tokens",
            "Restore any affected files from clean backup"
        ]),
        ("Authentication Security", [
            "Enable Multi-Factor Authentication (MFA) for all accounts",
            "Implement account lockout after 3 failed login attempts",
            "Use strong password policy (min 12 chars, special chars)",
            "Restrict login access to known IP addresses only"
        ]),
        ("Access Control", [
            "Apply strict bucket policies (least privilege principle)",
            "Restrict forensic-evidence and quarantine buckets to admin only",
            "Regularly rotate MinIO access keys every 30 days",
            "Audit all user permissions quarterly"
        ]),
        ("Monitoring & Prevention", [
            "Keep this detection tool running continuously",
            "Set up email alerts for all CRITICAL security events",
            "Enable MinIO audit logging to S3",
            "Conduct monthly penetration testing on cloud storage"
        ])
    ]

    for category, items in recommendations:
        story.append(Paragraph(f"<b>{category}:</b>", normal_style))
        for item in items:
            story.append(Paragraph(f"  • {item}", normal_style))
            story.append(Spacer(1, 2))
        story.append(Spacer(1, 6))

    story.append(Spacer(1, 12))

    # ─────────────────────────────────────────
    # FOOTER
    # ─────────────────────────────────────────

    story.append(HRFlowable(
        width="100%",
        thickness=2,
        color=colors.darkred
    ))
    story.append(Spacer(1, 6))

    footer_text = (
        f"<b>Report Generated By:</b> "
        f"Cloud Ransomware Detection & Forensics Tool v2.0<br/>"
        f"<b>Generated At:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
        f"<b>Case ID:</b> {case_id}<br/>"
        f"<b>Classification:</b> CONFIDENTIAL - FOR AUTHORIZED PERSONNEL ONLY"
    )

    story.append(Paragraph(footer_text, normal_style))

    # Build PDF
    doc.build(story)

    print(f"\n📄 [REPORT] PDF Report created successfully!")
    print(f"   File: {filename}")
    print(f"   Attacks covered: {', '.join(attacks) if attacks else 'None'}")

    return filename