from django import forms
from django.utils.html import strip_tags

from .models import Note


class WriteNoteForm(forms.ModelForm):
    class Meta:
        model = Note
        fields = ('content', 'receiver')
        widgets = {
            'content': forms.Textarea(attrs={'rows': 5}),
        }

    def clean_content(self):
        content = self.cleaned_data.get('content', '')
        # Remove HTML tags to mitigate XSS and ensure content is plain text
        cleaned = strip_tags(content)
        return cleaned


class ReplyForm(forms.ModelForm):
    class Meta:
        model = Note
        fields = ('content',)
        widgets = {
            'content': forms.Textarea(attrs={'rows': 5}),
        }

    def clean_content(self):
        content = self.cleaned_data.get('content', '')
        cleaned = strip_tags(content)
        return cleaned
