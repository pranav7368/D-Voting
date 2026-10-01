from pathlib import Path
import re
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.colors import HexColor

root=Path(__file__).parent; src=root/'D-Voting-Research-Paper.md'; out=root/'D-Voting-Research-Paper.pdf'
ss=getSampleStyleSheet()
ss.add(ParagraphStyle(name='TitleX',parent=ss['Title'],fontName='Times-Bold',fontSize=18,leading=22,alignment=TA_CENTER,textColor=HexColor('#16304E'),spaceAfter=10))
ss.add(ParagraphStyle(name='AuthorX',parent=ss['Normal'],fontName='Times-Roman',fontSize=10.5,leading=14,alignment=TA_CENTER,spaceAfter=12))
ss.add(ParagraphStyle(name='H1X',parent=ss['Heading1'],fontName='Times-Bold',fontSize=13,leading=16,textColor=HexColor('#16304E'),spaceBefore=10,spaceAfter=5,keepWithNext=True))
ss.add(ParagraphStyle(name='H2X',parent=ss['Heading2'],fontName='Times-Bold',fontSize=11,leading=14,textColor=HexColor('#1E4668'),spaceBefore=7,spaceAfter=3,keepWithNext=True))
ss.add(ParagraphStyle(name='BodyX',parent=ss['BodyText'],fontName='Times-Roman',fontSize=10.2,leading=13.2,alignment=TA_JUSTIFY,spaceAfter=6))
ss.add(ParagraphStyle(name='AbstractX',parent=ss['BodyText'],fontName='Times-Roman',fontSize=10,leading=13,leftIndent=10*mm,rightIndent=10*mm,alignment=TA_JUSTIFY,spaceAfter=7))
ss.add(ParagraphStyle(name='SmallX',parent=ss['BodyText'],fontName='Times-Roman',fontSize=8.3,leading=10,spaceAfter=1))
def fmt(s):
    s=s.replace('<sup>1</sup>','<super>1</super>').replace('<sup>2</sup>','<super>2</super>'); s=s.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;'); s=s.replace('&lt;super&gt;','<super>').replace('&lt;/super&gt;','</super>'); s=re.sub(r'\*\*(.+?)\*\*',r'<b>\1</b>',s); s=re.sub(r'\*(.+?)\*',r'<i>\1</i>',s); s=re.sub(r'`(.+?)`',r'<font name="Courier">\1</font>',s); return s
def footer(c,doc):
    c.saveState(); c.setFont('Times-Roman',8); c.setFillColor(HexColor('#58636E')); c.drawString(20*mm,12*mm,'D-Voting Research Paper'); c.drawRightString(190*mm,12*mm,f'Page {doc.page}'); c.restoreState()
lines=src.read_text(encoding='utf-8').splitlines(); story=[]; i=0; first=True
while i<len(lines):
    line=lines[i].strip()
    if not line: i+=1; continue
    if first and line.startswith('# '): story.append(Paragraph(fmt(line[2:]),ss['TitleX'])); first=False; i+=1; continue
    if line.startswith('**Pranav Kumar Singh**'):
        while i<len(lines) and lines[i].strip() and not lines[i].startswith('## '): story.append(Paragraph(fmt(lines[i].strip()),ss['AuthorX'])); i+=1
        continue
    if line.startswith('## '): story.append(Paragraph(fmt(line[3:]),ss['H1X'])); i+=1; continue
    if line.startswith('### '): story.append(Paragraph(fmt(line[4:]),ss['H2X'])); i+=1; continue
    if line.startswith('|'):
        rows=[]
        while i<len(lines) and lines[i].strip().startswith('|'):
            cells=[x.strip() for x in lines[i].strip().strip('|').split('|')]
            if not all(set(x)<=set('-:') for x in cells): rows.append([Paragraph(fmt(x),ss['SmallX']) for x in cells])
            i+=1
        if rows:
            t=Table(rows,repeatRows=1,hAlign='CENTER'); t.setStyle(TableStyle([('GRID',(0,0),(-1,-1),.35,colors.HexColor('#B5C0CB')),('BACKGROUND',(0,0),(-1,0),HexColor('#E8EEF5')),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),4),('RIGHTPADDING',(0,0),(-1,-1),4),('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3)])); story.extend([Spacer(1,3),t,Spacer(1,5)])
        continue
    if line.startswith('- '): story.append(Paragraph('• '+fmt(line[2:]),ss['BodyX'])); i+=1; continue
    if re.match(r'^\[\d+\]',line): story.append(Paragraph(fmt(line),ss['BodyX'])); i+=1; continue
    acc=[line]; i+=1
    while i<len(lines) and lines[i].strip() and not lines[i].startswith(('#','|','- ')): acc.append(lines[i].strip()); i+=1
    text=' '.join(acc); style=ss['AbstractX'] if text.startswith('Electronic voting must') else ss['BodyX']; story.append(Paragraph(fmt(text),style))
doc=SimpleDocTemplate(str(out),pagesize=A4,rightMargin=20*mm,leftMargin=20*mm,topMargin=18*mm,bottomMargin=18*mm,title='D-Voting Research Paper',author='Pranav Kumar Singh')
doc.build(story,onFirstPage=footer,onLaterPages=footer); print(out)
